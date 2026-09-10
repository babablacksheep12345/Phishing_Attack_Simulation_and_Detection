"""Web UI for Phishing Attack Simulation and Detection."""

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.detector.email_detector import EmailPhishingDetector
from src.detector.url_detector import URLPhishingDetector
from src.simulator.email_simulator import EmailSimulator
from src.simulator.scenario_generator import ScenarioGenerator
from src.utils.helpers import load_config

st.set_page_config(
    page_title="PhishGuard | Simulation & Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Theme & CSS
# ---------------------------------------------------------------------------
st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif;
    }

    /* ---- Main area background ---- */
    .stApp {
        background: linear-gradient(160deg, #f0f4ff 0%, #f8fafc 40%, #eef2ff 100%);
    }
    .main .block-container {
        padding-top: 1.2rem;
        max-width: 1180px;
    }

    /* ---- Sidebar ---- */
    section[data-testid="stSidebar"] {
        background: linear-gradient(195deg, #0b1220 0%, #111827 45%, #0f2744 100%) !important;
        border-right: 1px solid rgba(56, 189, 248, 0.25);
        box-shadow: 4px 0 24px rgba(0, 0, 0, 0.15);
    }
    section[data-testid="stSidebar"] > div {
        background: transparent !important;
    }
    section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
    section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] li {
        color: #cbd5e1;
    }
    section[data-testid="stSidebar"] hr {
        border-color: rgba(148, 163, 184, 0.2);
        margin: 1rem 0;
    }

    /* Sidebar logo block */
    .sidebar-brand {
        text-align: center;
        padding: 1.25rem 0.75rem 1rem;
        margin-bottom: 0.5rem;
        border-bottom: 1px solid rgba(56, 189, 248, 0.2);
    }
    .sidebar-brand .logo-ring {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 64px;
        height: 64px;
        border-radius: 18px;
        background: linear-gradient(135deg, #0ea5e9, #6366f1);
        box-shadow: 0 8px 24px rgba(14, 165, 233, 0.45);
        font-size: 1.75rem;
        margin-bottom: 0.75rem;
    }
    .sidebar-brand h2 {
        color: #f8fafc !important;
        font-size: 1.35rem !important;
        font-weight: 800 !important;
        margin: 0 !important;
        letter-spacing: -0.02em;
    }
    .sidebar-brand .tagline {
        color: #94a3b8 !important;
        font-size: 0.78rem !important;
        margin-top: 0.35rem !important;
    }
    .status-pill {
        display: inline-block;
        background: rgba(34, 197, 94, 0.15);
        color: #4ade80;
        border: 1px solid rgba(34, 197, 94, 0.35);
        border-radius: 999px;
        padding: 0.2rem 0.65rem;
        font-size: 0.72rem;
        font-weight: 600;
        margin-top: 0.6rem;
    }

    /* Sidebar nav label */
    .nav-label {
        color: #64748b !important;
        font-size: 0.68rem !important;
        font-weight: 700 !important;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        margin: 0.5rem 0 0.75rem 0.25rem !important;
    }

    /* Radio nav items */
    section[data-testid="stSidebar"] .stRadio > div {
        gap: 0.45rem;
    }
    section[data-testid="stSidebar"] .stRadio label {
        background: rgba(255, 255, 255, 0.04) !important;
        border: 1px solid rgba(148, 163, 184, 0.12) !important;
        border-radius: 12px !important;
        padding: 0.75rem 1rem !important;
        color: #e2e8f0 !important;
        font-weight: 600 !important;
        font-size: 0.92rem !important;
        transition: all 0.2s ease;
        width: 100%;
    }
    section[data-testid="stSidebar"] .stRadio label:hover {
        background: rgba(14, 165, 233, 0.12) !important;
        border-color: rgba(56, 189, 248, 0.35) !important;
        color: #ffffff !important;
    }
    section[data-testid="stSidebar"] .stRadio label[data-checked="true"],
    section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label:has(input:checked) {
        background: linear-gradient(135deg, rgba(14,165,233,0.25), rgba(99,102,241,0.2)) !important;
        border-color: rgba(56, 189, 248, 0.55) !important;
        color: #ffffff !important;
        box-shadow: 0 4px 14px rgba(14, 165, 233, 0.2);
    }
    section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label > div:first-child {
        display: none !important;
    }

    /* Sidebar stat cards */
    .sidebar-stat {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(148, 163, 184, 0.15);
        border-radius: 10px;
        padding: 0.65rem 0.75rem;
        text-align: center;
    }
    .sidebar-stat .num {
        color: #38bdf8;
        font-size: 1.1rem;
        font-weight: 800;
    }
    .sidebar-stat .lbl {
        color: #94a3b8;
        font-size: 0.68rem;
        font-weight: 500;
    }

    /* Sidebar footer */
    .sidebar-footer {
        background: rgba(0, 0, 0, 0.25);
        border: 1px solid rgba(148, 163, 184, 0.15);
        border-radius: 12px;
        padding: 0.85rem;
        margin-top: 0.5rem;
    }
    .sidebar-footer p {
        margin: 0.2rem 0 !important;
        font-size: 0.8rem !important;
        color: #94a3b8 !important;
    }
    .sidebar-footer b { color: #e2e8f0 !important; }
    .github-btn {
        display: block;
        text-align: center;
        background: linear-gradient(135deg, #0ea5e9, #6366f1);
        color: white !important;
        text-decoration: none !important;
        padding: 0.55rem 1rem;
        border-radius: 10px;
        font-weight: 600;
        font-size: 0.85rem;
        margin-top: 0.65rem;
        box-shadow: 0 4px 12px rgba(14, 165, 233, 0.3);
    }
    .github-btn:hover { opacity: 0.92; }

    /* ---- Hero ---- */
    .hero {
        background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 40%, #312e81 100%);
        padding: 2.2rem 2.5rem;
        border-radius: 20px;
        color: white;
        margin-bottom: 1.75rem;
        box-shadow: 0 16px 48px rgba(15, 23, 42, 0.3);
        position: relative;
        overflow: hidden;
    }
    .hero::before {
        content: '';
        position: absolute;
        top: -50%;
        right: -10%;
        width: 300px;
        height: 300px;
        background: radial-gradient(circle, rgba(56,189,248,0.15) 0%, transparent 70%);
        border-radius: 50%;
    }
    .hero h1 {
        color: white !important;
        font-size: 2.1rem !important;
        font-weight: 800 !important;
        margin-bottom: 0.5rem !important;
        letter-spacing: -0.03em;
        position: relative;
    }
    .hero p {
        color: #94a3b8 !important;
        font-size: 1.05rem !important;
        margin: 0 !important;
        max-width: 620px;
        position: relative;
    }
    .hero-badge {
        display: inline-block;
        background: rgba(56, 189, 248, 0.15);
        border: 1px solid rgba(56, 189, 248, 0.3);
        color: #7dd3fc;
        padding: 0.3rem 0.75rem;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-bottom: 0.75rem;
    }

    /* ---- Cards ---- */
    .metric-card {
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 16px;
        padding: 1.35rem;
        text-align: center;
        box-shadow: 0 4px 16px rgba(0,0,0,0.05);
        height: 100%;
        transition: transform 0.2s, box-shadow 0.2s;
    }
    .metric-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 24px rgba(0,0,0,0.08);
    }
    .metric-card .icon { font-size: 1.5rem; margin-bottom: 0.4rem; }
    .metric-card .value {
        font-size: 1.85rem;
        font-weight: 800;
        background: linear-gradient(135deg, #0ea5e9, #6366f1);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    .metric-card .label { font-size: 0.82rem; color: #64748b; margin-top: 0.3rem; font-weight: 500; }

    .feature-card {
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 16px;
        padding: 1.35rem;
        height: 100%;
        box-shadow: 0 2px 12px rgba(0,0,0,0.04);
        transition: transform 0.2s, border-color 0.2s;
    }
    .feature-card:hover {
        transform: translateY(-2px);
        border-color: #bae6fd;
    }
    .feature-card h4 { color: #0f172a; margin: 0 0 0.5rem 0; font-size: 1.02rem; font-weight: 700; }
    .feature-card p { color: #64748b; font-size: 0.88rem; margin: 0; line-height: 1.55; }

    .content-panel {
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 16px;
        padding: 1.5rem 1.75rem;
        margin-bottom: 1.25rem;
        box-shadow: 0 2px 12px rgba(0,0,0,0.04);
    }

    .verdict-box {
        border-radius: 14px;
        padding: 1.5rem;
        margin: 1rem 0;
        border: 1px solid #e2e8f0;
    }
    .verdict-danger {
        background: linear-gradient(135deg, #fef2f2 0%, #fff1f2 100%);
        border-left: 5px solid #ef4444;
    }
    .verdict-safe {
        background: linear-gradient(135deg, #f0fdf4 0%, #ecfdf5 100%);
        border-left: 5px solid #22c55e;
    }
    .verdict-title { font-size: 1.2rem; font-weight: 700; margin: 0 0 0.5rem 0; }
    .verdict-danger .verdict-title { color: #dc2626; }
    .verdict-safe .verdict-title { color: #16a34a; }

    .rule-chip {
        display: inline-block;
        background: #eff6ff;
        color: #1d4ed8;
        border: 1px solid #bfdbfe;
        border-radius: 20px;
        padding: 0.3rem 0.8rem;
        margin: 0.2rem 0.25rem 0.2rem 0;
        font-size: 0.78rem;
        font-weight: 600;
    }
    .rule-chip-danger {
        background: #fef2f2;
        color: #b91c1c;
        border-color: #fecaca;
    }

    .email-preview {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 14px;
        overflow: hidden;
        margin: 1rem 0;
        box-shadow: 0 6px 20px rgba(0,0,0,0.07);
    }
    .email-header {
        background: #f8fafc;
        padding: 1rem 1.25rem;
        border-bottom: 1px solid #e2e8f0;
    }
    .email-header .field { margin: 0.3rem 0; font-size: 0.9rem; color: #334155; }
    .email-header .field b { color: #0f172a; min-width: 60px; display: inline-block; }
    .email-body { padding: 1.25rem; white-space: pre-wrap; font-size: 0.95rem; color: #475569; line-height: 1.6; }

    .red-flag {
        background: #fff7ed;
        border-left: 3px solid #f97316;
        padding: 0.55rem 0.85rem;
        margin: 0.35rem 0;
        border-radius: 0 10px 10px 0;
        font-size: 0.86rem;
        color: #9a3412;
    }

    .url-card {
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 14px;
        padding: 1.25rem;
        margin: 0.75rem 0;
        box-shadow: 0 2px 10px rgba(0,0,0,0.04);
    }
    .url-text {
        font-family: 'Consolas', monospace;
        background: #f1f5f9;
        padding: 0.6rem 0.85rem;
        border-radius: 10px;
        font-size: 0.85rem;
        word-break: break-all;
        color: #0f172a;
        border: 1px solid #e2e8f0;
    }

    .section-title {
        font-size: 1.45rem;
        font-weight: 800;
        color: #0f172a;
        margin-bottom: 0.2rem;
        letter-spacing: -0.02em;
    }
    .section-sub {
        color: #64748b;
        font-size: 0.95rem;
        margin-bottom: 1.25rem;
    }

    .alert-safe {
        background: linear-gradient(135deg, #ecfdf5, #f0fdf4);
        border: 1px solid #86efac;
        border-radius: 12px;
        padding: 0.85rem 1rem;
        color: #166534;
        font-size: 0.9rem;
        margin-bottom: 0.75rem;
    }
    .alert-warn {
        background: linear-gradient(135deg, #fffbeb, #fef3c7);
        border: 1px solid #fcd34d;
        border-radius: 12px;
        padding: 0.85rem 1rem;
        color: #92400e;
        font-size: 0.9rem;
        margin-bottom: 0.75rem;
    }

    /* Primary buttons */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #0ea5e9, #6366f1) !important;
        border: none !important;
        border-radius: 12px !important;
        font-weight: 700 !important;
        padding: 0.6rem 1.5rem !important;
        box-shadow: 0 4px 14px rgba(14, 165, 233, 0.35) !important;
        transition: all 0.2s !important;
    }
    .stButton > button[kind="primary"]:hover {
        box-shadow: 0 6px 20px rgba(14, 165, 233, 0.45) !important;
        transform: translateY(-1px);
    }

    /* Inputs */
    .stTextInput > div > div,
    .stTextArea > div > div,
    .stSelectbox > div > div {
        border-radius: 10px !important;
    }

    footer { visibility: hidden; }
    footer:after {
        content: 'PhishGuard · Educational Use Only · CodeCT Technologies Internship';
        visibility: visible;
        display: block;
        text-align: center;
        color: #94a3b8;
        font-size: 0.8rem;
        padding: 1rem;
    }
</style>
""",
    unsafe_allow_html=True,
)

config = load_config()
email_detector = EmailPhishingDetector(config)
url_detector = URLPhishingDetector(config)
simulator = EmailSimulator()
scenario_gen = ScenarioGenerator()

NAV_ITEMS = [
    "🏠 Dashboard",
    "📧 Simulate",
    "✉️ Email Detector",
    "🔗 Website Detector",
    "🚀 Full Demo",
]

URL_DETECTION_RULES = [
    ("Trusted TLDs (.com, .io, .in, .ai)", "Legitimate extensions are NOT flagged unless impersonation is found"),
    ("Known Domains Whitelist", "Google, GitHub, PayPal, etc. and their subdomains are always safe"),
    ("Brand Typosquatting", "Catches paypa1.com, microsft-login.com, g00gle-security.com"),
    ("Suspicious TLD + Keywords", "Only flags .xyz/.tk domains that also have login/verify paths"),
    ("IP Address URL", "Sites using raw IP instead of a real domain name"),
    ("Homograph Attack", "Unicode lookalike characters in the domain"),
    ("@ Symbol Redirect", "Hidden URL redirect tricks"),
]


def render_hero(subtitle: str | None = None):
    text = subtitle or "Simulate phishing attacks for awareness training and detect phishing emails & malicious websites in real time."
    st.markdown(
        f"""
        <div class="hero">
            <div class="hero-badge">CYBERSECURITY AWARENESS PLATFORM</div>
            <h1>PhishGuard — Simulation & Detection</h1>
            <p>{text}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metric_cards():
    c1, c2, c3, c4 = st.columns(4)
    cards = [
        (c1, "🎯", "5", "Attack Scenarios"),
        (c2, "📨", "10+", "Email Rules"),
        (c3, "🔗", "8+", "URL Checks"),
        (c4, "🐍", "100%", "Python"),
    ]
    for col, icon, val, label in cards:
        with col:
            st.markdown(
                f'<div class="metric-card"><div class="icon">{icon}</div>'
                f'<div class="value">{val}</div><div class="label">{label}</div></div>',
                unsafe_allow_html=True,
            )


def risk_color(risk: str) -> str:
    return {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}.get(risk, "#64748b")


def render_rule_chips(rules: list[str], danger: bool = True):
    chips = "".join(
        f'<span class="rule-chip{" rule-chip-danger" if danger else ""}">{r.replace("_", " ").title()}</span>'
        for r in rules
    )
    st.markdown(chips, unsafe_allow_html=True)


def render_detection_result(result):
    is_bad = result.is_phishing
    box_class = "verdict-danger" if is_bad else "verdict-safe"
    verdict_text = "PHISHING / MALICIOUS WEBSITE DETECTED" if is_bad else "APPEARS LEGITIMATE"
    icon = "🚨" if is_bad else "✅"

    st.markdown(
        f"""
        <div class="verdict-box {box_class}">
            <p class="verdict-title">{icon} {verdict_text}</p>
            <p style="margin:0;color:#64748b;">
                <b>Confidence:</b> {result.confidence:.1%} &nbsp;•&nbsp;
                <b>Risk:</b> <span style="color:{risk_color(result.risk_level)};font-weight:700;">{result.risk_level}</span>
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.progress(result.confidence, text=f"Threat score: {result.confidence:.0%}")
    if result.triggered_rules:
        st.markdown("**Triggered rules:**")
        render_rule_chips(result.triggered_rules, danger=is_bad)
    if result.details:
        with st.expander("Technical details"):
            st.json(result.details)


def render_email_preview(email_data: dict):
    email = email_data["email"]
    diff_colors = {"easy": "#22c55e", "medium": "#f97316", "hard": "#ef4444"}
    diff_color = diff_colors.get(email_data.get("difficulty", "medium"), "#64748b")

    st.markdown(
        f"""
        <div class="email-preview">
            <div style="padding:0.85rem 1.25rem;background:linear-gradient(135deg,#0f172a,#1e3a5f);color:white;
                display:flex;justify-content:space-between;align-items:center;">
                <span style="font-weight:700;">📧 {email_data['scenario']}</span>
                <span style="background:{diff_color};padding:0.25rem 0.7rem;border-radius:999px;
                    font-size:0.72rem;font-weight:700;">{email_data.get('difficulty','medium').upper()}</span>
            </div>
            <div class="email-header">
                <div class="field"><b>From:</b> {email['from_display']} &lt;{email['from_address']}&gt;</div>
                <div class="field"><b>Subject:</b> {email['subject']}</div>
            </div>
            <div class="email-body">{email['body']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("**🚩 Red flags:**")
    for flag in email_data["red_flags"]:
        st.markdown(f'<div class="red-flag">⚠️ {flag}</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        """
        <div class="sidebar-brand">
            <div class="logo-ring">🛡️</div>
            <h2>PhishGuard</h2>
            <p class="tagline">Simulation & Detection Suite</p>
            <span class="status-pill">● System Online</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<p class="nav-label">Navigation</p>', unsafe_allow_html=True)
    page = st.radio("Navigate", NAV_ITEMS, label_visibility="collapsed")

    st.markdown('<p class="nav-label">Quick Stats</p>', unsafe_allow_html=True)
    s1, s2 = st.columns(2)
    with s1:
        st.markdown('<div class="sidebar-stat"><div class="num">5</div><div class="lbl">Scenarios</div></div>', unsafe_allow_html=True)
    with s2:
        st.markdown('<div class="sidebar-stat"><div class="num">9</div><div class="lbl">Tests Pass</div></div>', unsafe_allow_html=True)

    st.markdown(
        """
        <div class="sidebar-footer">
            <p><b>Author:</b> Shikha</p>
            <p><b>Org:</b> CodeCT Technologies</p>
            <p><b>Project:</b> Internship 2026</p>
            <a class="github-btn" href="https://github.com/Shikha-Upadhyay13/Phishing_Attack_Simulation_and_Detection" target="_blank">
                View on GitHub →
            </a>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
if page == "🏠 Dashboard":
    render_hero()
    render_metric_cards()
    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    for col, title, desc in [
        (col1, "📧 Phishing Simulator", "Generate credential theft, fake invoice, prize scam & more."),
        (col2, "✉️ Email Detector", "Scan for urgency, spoofed senders, typosquat domains & bad links."),
        (col3, "🔗 Website Detector", "Catch typosquatted URLs, suspicious TLDs & phishing pages."),
    ]:
        with col:
            st.markdown(f'<div class="feature-card"><h4>{title}</h4><p>{desc}</p></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<p class="section-title">How Website Detection Works</p>', unsafe_allow_html=True)
    st.markdown('<p class="section-sub">Smart layered analysis — trusted domains stay safe, impersonators get caught.</p>', unsafe_allow_html=True)

    cols = st.columns(2)
    for i, (name, desc) in enumerate(URL_DETECTION_RULES):
        with cols[i % 2]:
            st.markdown(f'<div class="feature-card" style="margin-bottom:0.75rem;"><h4>🔍 {name}</h4><p>{desc}</p></div>', unsafe_allow_html=True)

elif page == "📧 Simulate":
    render_hero("Generate realistic phishing emails for security awareness training.")
    st.markdown('<div class="content-panel">', unsafe_allow_html=True)
    st.markdown('<p class="section-title">Phishing Email Simulator</p>', unsafe_allow_html=True)
    st.markdown('<p class="section-sub">Pick a scenario and generate a training email with red flags explained.</p>', unsafe_allow_html=True)

    col1, col2 = st.columns([2, 1])
    with col1:
        scenario = st.selectbox("Attack scenario", ["Random"] + scenario_gen.list_scenarios(),
                                format_func=lambda x: x.replace("_", " ").title() if x != "Random" else "🎲 Random")
    with col2:
        count = st.number_input("Emails to generate", 1, 5, 1)

    if st.button("⚡ Generate Simulation", type="primary", use_container_width=True):
        emails = simulator.simulate_campaign(int(count)) if scenario == "Random" else [simulator.simulate_single(scenario)] * int(count)
        st.session_state["simulated_emails"] = emails
    st.markdown('</div>', unsafe_allow_html=True)

    if "simulated_emails" in st.session_state:
        for email_data in st.session_state["simulated_emails"]:
            render_email_preview(email_data)
            if st.button("🔍 Analyze this email", key=f"analyze_{email_data['simulation_id']}"):
                render_detection_result(email_detector.analyze_email_dict(email_data["email"]))

elif page == "✉️ Email Detector":
    render_hero("Paste any suspicious email — we scan 10+ phishing indicators instantly.")
    st.markdown('<div class="content-panel">', unsafe_allow_html=True)
    st.markdown('<p class="section-title">Email Phishing Detector</p>', unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        from_display = st.text_input("Display name", "PayPal Security")
        from_address = st.text_input("Sender email", "security@paypa1-secure.com")
    with c2:
        subject = st.text_input("Subject", "URGENT: Verify Your Account Immediately")
        st.caption("Phishing emails often use ALL CAPS and urgency.")

    body = st.text_area("Email body",
        "Dear User,\n\nYour account will be suspended within 24 hours.\n\nVerify now: http://paypa1-secure.com/login\n\nAct immediately!",
        height=160)

    if st.button("🔍 Analyze Email", type="primary", use_container_width=True):
        render_detection_result(email_detector.analyze(subject, body, from_address, from_display))
    st.markdown('</div>', unsafe_allow_html=True)

elif page == "🔗 Website Detector":
    render_hero("Check any URL before you click — catch phishing login pages and typosquatted domains.")
    st.markdown('<div class="content-panel">', unsafe_allow_html=True)
    st.markdown('<p class="section-title">Website / URL Detector</p>', unsafe_allow_html=True)

    st.markdown('<div class="alert-safe">✅ <b>Safe by default:</b> .com, .io, .in, .ai, .org sites are trusted unless they impersonate a brand.</div>', unsafe_allow_html=True)
    st.markdown('<div class="alert-warn">🚨 <b>Flagged when:</b> typosquatting (paypa1.com), suspicious TLD + login (.xyz/verify), or IP-based URLs.</div>', unsafe_allow_html=True)

    url_input = st.text_input("Enter URL", "http://paypa1-secure.com/login/verify")

    st.markdown("**Quick samples:**")
    sc1, sc2, sc3 = st.columns(3)
    samples = {
        "🚨 Phishing": ["http://paypa1-secure.com/login", "http://microsft-login.com/signin", "http://secure-banking-update.xyz/verify"],
        "⚠️ Suspicious": ["http://g00gle-security.com/auth", "http://192.168.1.100/login", "http://amaz0n-billing.net/invoice"],
        "✅ Legitimate": ["https://www.github.com/login", "https://www.google.com", "https://www.paypal.com/signin"],
    }
    selected = []
    for col, (label, urls) in zip([sc1, sc2, sc3], samples.items()):
        with col:
            st.markdown(f"**{label}**")
            for url in urls:
                if st.checkbox(url.split("//")[1][:28], key=f"s_{url}"):
                    selected.append(url)

    urls = selected or ([url_input] if url_input.strip() else [])
    if st.button("🔍 Scan URL(s)", type="primary", use_container_width=True) and urls:
        for url in urls:
            st.markdown(f'<div class="url-card"><p style="margin:0 0 0.5rem;font-weight:700;">Analyzing</p><div class="url-text">{url}</div></div>', unsafe_allow_html=True)
            render_detection_result(url_detector.analyze(url))

    with st.expander("📋 All detection rules"):
        for name, desc in URL_DETECTION_RULES:
            st.markdown(f"**{name}** — {desc}")
    st.markdown('</div>', unsafe_allow_html=True)

elif page == "🚀 Full Demo":
    render_hero("End-to-end demo: simulate attacks, detect emails, scan URLs.")
    st.markdown('<div class="content-panel">', unsafe_allow_html=True)
    demo_count = st.slider("Attack scenarios", 1, 5, 3)

    if st.button("🚀 Run Full Demo", type="primary", use_container_width=True):
        with st.spinner("Running simulation & detection..."):
            emails = simulator.simulate_campaign(demo_count)
            email_hits = url_hits = 0
            all_urls = []

            st.markdown("### 📧 Step 1 — Simulated Emails")
            for ed in emails:
                render_email_preview(ed)

            st.markdown("### 🔍 Step 2 — Email Detection")
            for ed in emails:
                r = email_detector.analyze_email_dict(ed["email"])
                email_hits += r.is_phishing
                all_urls.extend(ed["email"].get("urls", []))
                color = "#ef4444" if r.is_phishing else "#22c55e"
                label = "PHISHING" if r.is_phishing else "SAFE"
                st.markdown(f"**{ed['email']['subject']}** — <span style='color:{color};font-weight:700'>{label}</span> ({r.confidence:.0%})", unsafe_allow_html=True)

            st.markdown("### 🔗 Step 3 — URL Detection")
            for url in all_urls:
                r = url_detector.analyze(url)
                url_hits += r.is_phishing
                color = "#ef4444" if r.is_phishing else "#22c55e"
                label = "PHISHING" if r.is_phishing else "SAFE"
                st.markdown(f"`{url}` — <span style='color:{color};font-weight:700'>{label}</span> ({r.confidence:.0%})", unsafe_allow_html=True)

            m1, m2, m3 = st.columns(3)
            m1.metric("Emails flagged", f"{email_hits}/{len(emails)}")
            m2.metric("URLs caught", f"{url_hits}/{len(all_urls)}")
            m3.metric("Detection rate", f"{(email_hits + url_hits) / max(len(emails) + len(all_urls), 1):.0%}")
    st.markdown('</div>', unsafe_allow_html=True)
