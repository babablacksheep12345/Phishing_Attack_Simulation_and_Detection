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
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    .main .block-container {
        padding-top: 1.5rem;
        max-width: 1200px;
    }

    .hero {
        background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 50%, #0c4a6e 100%);
        padding: 2rem 2.5rem;
        border-radius: 16px;
        color: white;
        margin-bottom: 1.5rem;
        box-shadow: 0 10px 40px rgba(15, 23, 42, 0.25);
    }
    .hero h1 { color: white !important; font-size: 2rem !important; margin-bottom: 0.4rem !important; }
    .hero p { color: #94a3b8 !important; font-size: 1.05rem !important; margin: 0 !important; }

    .metric-card {
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        padding: 1.25rem;
        text-align: center;
        box-shadow: 0 2px 8px rgba(0,0,0,0.04);
        height: 100%;
    }
    .metric-card .value { font-size: 1.75rem; font-weight: 700; color: #0f172a; }
    .metric-card .label { font-size: 0.85rem; color: #64748b; margin-top: 0.25rem; }

    .feature-card {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        padding: 1.25rem;
        height: 100%;
    }
    .feature-card h4 { color: #0f172a; margin: 0 0 0.5rem 0; font-size: 1rem; }
    .feature-card p { color: #64748b; font-size: 0.9rem; margin: 0; line-height: 1.5; }

    .verdict-box {
        border-radius: 12px;
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
    .verdict-title { font-size: 1.25rem; font-weight: 700; margin: 0 0 0.5rem 0; }
    .verdict-danger .verdict-title { color: #dc2626; }
    .verdict-safe .verdict-title { color: #16a34a; }

    .rule-chip {
        display: inline-block;
        background: #eff6ff;
        color: #1d4ed8;
        border: 1px solid #bfdbfe;
        border-radius: 20px;
        padding: 0.25rem 0.75rem;
        margin: 0.2rem 0.25rem 0.2rem 0;
        font-size: 0.8rem;
        font-weight: 500;
    }
    .rule-chip-danger {
        background: #fef2f2;
        color: #b91c1c;
        border-color: #fecaca;
    }

    .email-preview {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        overflow: hidden;
        margin: 1rem 0;
        box-shadow: 0 4px 12px rgba(0,0,0,0.06);
    }
    .email-header {
        background: #f1f5f9;
        padding: 1rem 1.25rem;
        border-bottom: 1px solid #e2e8f0;
    }
    .email-header .field { margin: 0.3rem 0; font-size: 0.9rem; color: #334155; }
    .email-header .field b { color: #0f172a; min-width: 60px; display: inline-block; }
    .email-body { padding: 1.25rem; white-space: pre-wrap; font-size: 0.95rem; color: #475569; line-height: 1.6; }

    .red-flag {
        background: #fff7ed;
        border-left: 3px solid #f97316;
        padding: 0.5rem 0.75rem;
        margin: 0.35rem 0;
        border-radius: 0 8px 8px 0;
        font-size: 0.88rem;
        color: #9a3412;
    }

    .url-card {
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        padding: 1.25rem;
        margin: 0.75rem 0;
    }
    .url-text {
        font-family: monospace;
        background: #f1f5f9;
        padding: 0.5rem 0.75rem;
        border-radius: 8px;
        font-size: 0.85rem;
        word-break: break-all;
        color: #0f172a;
    }

    .section-title {
        font-size: 1.35rem;
        font-weight: 700;
        color: #0f172a;
        margin-bottom: 0.25rem;
    }
    .section-sub {
        color: #64748b;
        font-size: 0.95rem;
        margin-bottom: 1.25rem;
    }

    div[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f172a 0%, #1e293b 100%);
    }
    div[data-testid="stSidebar"] .stMarkdown, div[data-testid="stSidebar"] label {
        color: #e2e8f0 !important;
    }
    div[data-testid="stSidebar"] .stRadio label {
        color: #cbd5e1 !important;
    }

    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px 8px 0 0;
        padding: 0.6rem 1.2rem;
        font-weight: 600;
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

URL_DETECTION_RULES = [
    ("Typosquatting", "Detects domains mimicking brands (paypa1.com, microsft-login.com)"),
    ("Suspicious TLD", "Flags risky extensions like .xyz, .tk, .club"),
    ("IP Address URL", "Sites using raw IP instead of a domain name"),
    ("Homograph Attack", "Unicode characters that look like real letters"),
    ("Missing HTTPS", "Non-encrypted HTTP connections"),
    ("Suspicious Keywords", "login, verify, secure in untrusted domains"),
    ("@ Symbol Redirect", "URL obfuscation tricks"),
    ("DNS Check", "Domains that fail to resolve"),
]


def render_hero():
    st.markdown(
        """
        <div class="hero">
            <h1>🛡️ PhishGuard — Simulation & Detection</h1>
            <p>Simulate phishing attacks for awareness training and detect fake emails & malicious websites in real time.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metric_cards():
    c1, c2, c3, c4 = st.columns(4)
    cards = [
        (c1, "5", "Attack Scenarios"),
        (c2, "10+", "Email Detection Rules"),
        (c3, "8+", "Fake Website Checks"),
        (c4, "100%", "Python Powered"),
    ]
    for col, val, label in cards:
        with col:
            st.markdown(
                f'<div class="metric-card"><div class="value">{val}</div><div class="label">{label}</div></div>',
                unsafe_allow_html=True,
            )


def risk_color(risk: str) -> str:
    return {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}.get(risk, "#64748b")


def render_rule_chips(rules: list[str], danger: bool = True):
    chips = ""
    for rule in rules:
        cls = "rule-chip rule-chip-danger" if danger else "rule-chip"
        chips += f'<span class="{cls}">{rule.replace("_", " ").title()}</span>'
    st.markdown(chips, unsafe_allow_html=True)


def render_detection_result(result, title: str = "Analysis Result"):
    is_bad = result.is_phishing
    box_class = "verdict-danger" if is_bad else "verdict-safe"
    verdict_text = "PHISHING / FAKE WEBSITE DETECTED" if is_bad else "APPEARS LEGITIMATE"
    icon = "🚨" if is_bad else "✅"

    st.markdown(
        f"""
        <div class="verdict-box {box_class}">
            <p class="verdict-title">{icon} {verdict_text}</p>
            <p style="margin:0;color:#64748b;">
                <b>Confidence:</b> {result.confidence:.1%} &nbsp;•&nbsp;
                <b>Risk Level:</b> <span style="color:{risk_color(result.risk_level)};font-weight:600;">{result.risk_level}</span>
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.progress(result.confidence, text=f"Threat score: {result.confidence:.0%}")

    if result.triggered_rules:
        st.markdown("**Triggered detection rules:**")
        render_rule_chips(result.triggered_rules, danger=is_bad)

    if result.details:
        with st.expander("Technical details", expanded=False):
            st.json(result.details)


def render_email_preview(email_data: dict):
    email = email_data["email"]
    difficulty_colors = {"easy": "#22c55e", "medium": "#f97316", "hard": "#ef4444"}
    diff_color = difficulty_colors.get(email_data.get("difficulty", "medium"), "#64748b")

    st.markdown(
        f"""
        <div class="email-preview">
            <div style="padding:0.75rem 1.25rem;background:#0f172a;color:white;display:flex;justify-content:space-between;align-items:center;">
                <span style="font-weight:600;">📧 {email_data['scenario']}</span>
                <span style="background:{diff_color};padding:0.2rem 0.6rem;border-radius:12px;font-size:0.75rem;font-weight:600;">
                    {email_data.get('difficulty', 'medium').upper()}
                </span>
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

    st.markdown("**🚩 Red flags to spot:**")
    for flag in email_data["red_flags"]:
        st.markdown(f'<div class="red-flag">⚠️ {flag}</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🛡️ PhishGuard")
    st.markdown("Cybersecurity awareness platform")
    st.divider()
    page = st.radio(
        "Navigate",
        ["🏠 Dashboard", "📧 Simulate", "✉️ Email Detector", "🔗 Fake Website Detector", "🚀 Full Demo"],
        label_visibility="collapsed",
    )
    st.divider()
    st.markdown("**Project by:** Shikha")
    st.markdown("**Internship:** CodeCT Technologies")
    st.markdown(
        "[View on GitHub](https://github.com/Shikha-Upadhyay13/Phishing_Attack_Simulation_and_Detection)"
    )

render_hero()

# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
if page == "🏠 Dashboard":
    render_metric_cards()
    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    features = [
        (col1, "📧 Phishing Simulator", "Generate realistic attack scenarios — credential theft, fake invoices, prize scams, and more."),
        (col2, "✉️ Email Detector", "Analyze emails for urgency tactics, spoofed senders, typosquatted domains, and malicious links."),
        (col3, "🔗 Fake Website Detector", "Identify typosquatted URLs, suspicious TLDs, homograph attacks, and phishing login pages."),
    ]
    for col, title, desc in features:
        with col:
            st.markdown(
                f'<div class="feature-card"><h4>{title}</h4><p>{desc}</p></div>',
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<p class="section-title">Fake Website Detection — How It Works</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="section-sub">Our URL analyzer checks every link against multiple security heuristics.</p>',
        unsafe_allow_html=True,
    )

    rule_cols = st.columns(2)
    for i, (name, desc) in enumerate(URL_DETECTION_RULES):
        with rule_cols[i % 2]:
            st.markdown(
                f"""
                <div class="feature-card" style="margin-bottom:0.75rem;">
                    <h4>🔍 {name}</h4>
                    <p>{desc}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

elif page == "📧 Simulate":
    st.markdown('<p class="section-title">Phishing Email Simulator</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="section-sub">Generate realistic phishing emails for security awareness training.</p>',
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns([2, 1])
    with col1:
        scenario = st.selectbox(
            "Attack scenario",
            ["Random"] + scenario_gen.list_scenarios(),
            format_func=lambda x: x.replace("_", " ").title() if x != "Random" else "🎲 Random",
        )
    with col2:
        count = st.number_input("Emails to generate", min_value=1, max_value=5, value=1)

    if st.button("⚡ Generate Simulation", type="primary", use_container_width=True):
        if scenario == "Random":
            emails = simulator.simulate_campaign(int(count))
        else:
            emails = [simulator.simulate_single(scenario)] * int(count)

        st.session_state["simulated_emails"] = emails

    if "simulated_emails" in st.session_state:
        for email_data in st.session_state["simulated_emails"]:
            render_email_preview(email_data)
            if st.button("🔍 Analyze this email", key=f"analyze_{email_data['simulation_id']}"):
                result = email_detector.analyze_email_dict(email_data["email"])
                render_detection_result(result)

elif page == "✉️ Email Detector":
    st.markdown('<p class="section-title">Email Phishing Detector</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="section-sub">Paste suspicious email content — we scan for 10+ phishing indicators.</p>',
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)
    with col1:
        from_display = st.text_input("Display name", "PayPal Security")
        from_address = st.text_input("Sender email", "security@paypa1-secure.com")
    with col2:
        subject = st.text_input("Subject line", "URGENT: Verify Your Account Immediately")
        st.caption("Tip: Phishing emails often use ALL CAPS and urgency.")

    body = st.text_area(
        "Email body",
        "Dear User,\n\nYour account will be suspended within 24 hours.\n\nVerify now: http://paypa1-secure.com/login\n\nAct immediately!\n\nSecurity Team",
        height=180,
    )

    if st.button("🔍 Analyze Email", type="primary", use_container_width=True):
        result = email_detector.analyze(
            subject=subject,
            body=body,
            from_address=from_address,
            from_display=from_display,
        )
        render_detection_result(result)

elif page == "🔗 Fake Website Detector":
    st.markdown('<p class="section-title">Fake Website / URL Detector</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="section-sub">Detect typosquatted domains, fake login pages, and malicious URLs before you click.</p>',
        unsafe_allow_html=True,
    )

    st.info("💡 **Example:** `paypa1-secure.com` mimics PayPal using character substitution (1 → l)")

    url_input = st.text_input(
        "Enter URL to analyze",
        "http://paypa1-secure.com/login/verify",
        placeholder="https://suspicious-site.xyz/login",
    )

    st.markdown("**Quick test samples:**")
    sample_cols = st.columns(3)
    samples = {
        "🚨 Phishing": [
            "http://paypa1-secure.com/login",
            "http://microsft-login.com/signin",
            "http://secure-banking-update.xyz/verify",
        ],
        "⚠️ Suspicious": [
            "http://g00gle-security.com/auth",
            "http://192.168.1.100/login",
            "http://amaz0n-billing.net/invoice",
        ],
        "✅ Legitimate": [
            "https://www.github.com/login",
            "https://www.google.com",
            "https://www.paypal.com/signin",
        ],
    }

    selected_samples = []
    for col, (label, urls) in zip(sample_cols, samples.items()):
        with col:
            st.markdown(f"**{label}**")
            for url in urls:
                if st.checkbox(url.split("//")[1][:30], key=f"sample_{url}"):
                    selected_samples.append(url)

    urls_to_check = selected_samples if selected_samples else ([url_input] if url_input.strip() else [])

    if st.button("🔍 Scan URL(s)", type="primary", use_container_width=True) and urls_to_check:
        for url in urls_to_check:
            result = url_detector.analyze(url)
            st.markdown(
                f"""
                <div class="url-card">
                    <p style="margin:0 0 0.5rem 0;font-weight:600;color:#0f172a;">Analyzing URL</p>
                    <div class="url-text">{url}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            render_detection_result(result)

    with st.expander("📋 All detection rules explained"):
        for name, desc in URL_DETECTION_RULES:
            st.markdown(f"**{name}** — {desc}")

elif page == "🚀 Full Demo":
    st.markdown('<p class="section-title">Full End-to-End Demo</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="section-sub">Simulate attacks → detect phishing emails → scan malicious URLs → view results.</p>',
        unsafe_allow_html=True,
    )

    demo_count = st.slider("Number of attack scenarios", 1, 5, 3)

    if st.button("🚀 Run Full Demo", type="primary", use_container_width=True):
        with st.spinner("Running simulation and detection..."):
            emails = simulator.simulate_campaign(demo_count)
            email_hits = 0
            url_hits = 0
            all_urls = []

            st.markdown("### Step 1 — Simulated Phishing Emails")
            for email_data in emails:
                render_email_preview(email_data)

            st.markdown("### Step 2 — Email Detection")
            for email_data in emails:
                email = email_data["email"]
                result = email_detector.analyze_email_dict(email)
                if result.is_phishing:
                    email_hits += 1
                all_urls.extend(email.get("urls", []))

                cols = st.columns([3, 1, 1])
                with cols[0]:
                    st.markdown(f"**{email['subject']}**")
                with cols[1]:
                    st.markdown(
                        f"<span style='color:{'#ef4444' if result.is_phishing else '#22c55e'};font-weight:700;'>"
                        f"{'PHISHING' if result.is_phishing else 'SAFE'}</span>",
                        unsafe_allow_html=True,
                    )
                with cols[2]:
                    st.markdown(f"{result.confidence:.0%}")

            st.markdown("### Step 3 — Fake Website Detection")
            for url in all_urls:
                result = url_detector.analyze(url)
                if result.is_phishing:
                    url_hits += 1
                cols = st.columns([3, 1, 1])
                with cols[0]:
                    st.code(url, language=None)
                with cols[1]:
                    st.markdown(
                        f"<span style='color:{'#ef4444' if result.is_phishing else '#22c55e'};font-weight:700;'>"
                        f"{'FAKE' if result.is_phishing else 'SAFE'}</span>",
                        unsafe_allow_html=True,
                    )
                with cols[2]:
                    st.markdown(f"{result.confidence:.0%}")

            st.markdown("### Summary")
            m1, m2, m3 = st.columns(3)
            m1.metric("Emails flagged", f"{email_hits}/{len(emails)}")
            m2.metric("Fake URLs caught", f"{url_hits}/{len(all_urls)}")
            m3.metric("Detection rate", f"{((email_hits + url_hits) / max(len(emails) + len(all_urls), 1)):.0%}")

            if email_hits == len(emails) and url_hits == len(all_urls):
                st.success("All simulated threats were successfully detected!")
            else:
                st.warning(f"Detected {email_hits}/{len(emails)} emails and {url_hits}/{len(all_urls)} URLs.")

st.markdown("---")
st.caption(
    "Educational use only · Built for CodeCT Technologies Internship · "
    "[GitHub Repository](https://github.com/Shikha-Upadhyay13/Phishing_Attack_Simulation_and_Detection)"
)
