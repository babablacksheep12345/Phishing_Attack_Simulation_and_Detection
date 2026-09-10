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
    page_title="Phishing Simulation & Detection",
    page_icon="🛡️",
    layout="wide",
)

config = load_config()
email_detector = EmailPhishingDetector(config)
url_detector = URLPhishingDetector(config)
simulator = EmailSimulator()
scenario_gen = ScenarioGenerator()


def verdict_badge(is_phishing: bool) -> str:
    return "🔴 PHISHING" if is_phishing else "🟢 SAFE"


def risk_color(risk: str) -> str:
    colors = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#28a745"}
    return colors.get(risk, "#6c757d")


def render_detection_result(result, label: str):
    color = "#dc3545" if result.is_phishing else "#28a745"
    st.markdown(
        f"""
        <div style="padding:16px;border-radius:8px;border-left:5px solid {color};background:#f8f9fa;margin:8px 0;">
            <h4 style="margin:0;color:{color}">{label}: {"PHISHING DETECTED" if result.is_phishing else "LEGITIMATE"}</h4>
            <p style="margin:4px 0"><b>Confidence:</b> {result.confidence:.1%} &nbsp;|&nbsp;
            <b>Risk:</b> <span style="color:{risk_color(result.risk_level)}">{result.risk_level}</span></p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if result.triggered_rules:
        st.write("**Triggered rules:**", ", ".join(result.triggered_rules))
    if result.details:
        with st.expander("Details"):
            st.json(result.details)


st.title("🛡️ Phishing Attack Simulation & Detection")
st.caption("Educational security awareness tool — simulate attacks and detect phishing emails & fake websites.")

tab1, tab2, tab3, tab4 = st.tabs(["📧 Simulate", "🔍 Detect Email", "🔗 Detect URL", "🚀 Full Demo"])

with tab1:
    st.header("Phishing Email Simulator")
    st.info("Generates realistic phishing scenarios for security awareness training.")

    col1, col2 = st.columns(2)
    with col1:
        scenario = st.selectbox(
            "Scenario type",
            ["Random"] + scenario_gen.list_scenarios(),
            format_func=lambda x: x.replace("_", " ").title() if x != "Random" else "Random",
        )
    with col2:
        count = st.number_input("Number of emails", min_value=1, max_value=5, value=1)

    if st.button("Generate Simulation", type="primary"):
        if scenario == "Random":
            emails = simulator.simulate_campaign(int(count))
        else:
            emails = [simulator.simulate_single(scenario)] * int(count)

        for email_data in emails:
            email = email_data["email"]
            st.markdown(f"### {email_data['scenario']} ({email_data['difficulty']})")
            st.markdown(f"**From:** {email['from_display']} `<{email['from_address']}>`")
            st.markdown(f"**Subject:** {email['subject']}")
            st.text(email["body"])
            st.markdown("**Red flags to identify:**")
            for flag in email_data["red_flags"]:
                st.markdown(f"- {flag}")
            st.divider()

with tab2:
    st.header("Email Phishing Detector")
    st.info("Paste email content to analyze for phishing indicators.")

    from_display = st.text_input("Display name", "PayPal Security")
    from_address = st.text_input("Sender email", "security@paypa1-secure.com")
    subject = st.text_input("Subject", "URGENT: Verify Your Account")
    body = st.text_area(
        "Email body",
        "Dear User,\n\nYour account will be suspended. Verify now: http://paypa1-secure.com/login\n\nAct immediately!",
        height=150,
    )

    if st.button("Analyze Email", type="primary"):
        result = email_detector.analyze(
            subject=subject,
            body=body,
            from_address=from_address,
            from_display=from_display,
        )
        render_detection_result(result, "Verdict")

with tab3:
    st.header("Fake Website / URL Detector")
    st.info("Check if a URL is potentially malicious or a phishing site.")

    url_input = st.text_input(
        "Enter URL",
        "http://paypa1-secure.com/login/verify",
        placeholder="https://example.com/login",
    )

    sample_urls = st.multiselect(
        "Or pick sample URLs",
        [
            "http://paypa1-secure.com/login",
            "http://microsft-login.com/signin",
            "http://secure-banking-update.xyz/verify",
            "https://www.github.com/login",
            "https://www.google.com",
        ],
    )

    urls_to_check = sample_urls if sample_urls else ([url_input] if url_input else [])

    if st.button("Analyze URL(s)", type="primary") and urls_to_check:
        for url in urls_to_check:
            result = url_detector.analyze(url)
            st.markdown(f"**URL:** `{url}`")
            render_detection_result(result, "Verdict")
            st.divider()

with tab4:
    st.header("Full Demo")
    st.info("Simulates phishing attacks, runs detection, and shows results.")

    demo_count = st.slider("Scenarios to simulate", 1, 5, 3)

    if st.button("Run Full Demo", type="primary"):
        emails = simulator.simulate_campaign(demo_count)
        email_hits = 0
        url_hits = 0
        all_urls = []

        st.subheader("Step 1: Simulated Phishing Emails")
        for email_data in emails:
            email = email_data["email"]
            with st.expander(f"{email_data['scenario']} — {email['subject']}"):
                st.markdown(f"**From:** {email['from_display']} `<{email['from_address']}>`")
                st.text(email["body"])
                st.markdown("**Red flags:** " + " | ".join(email_data["red_flags"]))

        st.subheader("Step 2: Email Detection Results")
        for email_data in emails:
            email = email_data["email"]
            result = email_detector.analyze_email_dict(email)
            if result.is_phishing:
                email_hits += 1
            all_urls.extend(email.get("urls", []))
            st.markdown(f"**{email['subject']}** → {verdict_badge(result.is_phishing)} ({result.confidence:.1%})")

        st.subheader("Step 3: URL Detection Results")
        for url in all_urls:
            result = url_detector.analyze(url)
            if result.is_phishing:
                url_hits += 1
            st.markdown(f"`{url}` → {verdict_badge(result.is_phishing)} ({result.confidence:.1%})")

        st.success(f"Email detection: {email_hits}/{len(emails)} flagged | URL detection: {url_hits}/{len(all_urls)} flagged")

st.divider()
st.caption(
    "Built for cybersecurity education & internship project | "
    "[GitHub](https://github.com/Shikha-Upadhyay13/Phishing_Attack_Simulation_and_Detection)"
)
