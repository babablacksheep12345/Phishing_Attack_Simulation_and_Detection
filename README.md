# Phishing Attack Simulation and Detection

A Python-based security awareness project that **simulates phishing attacks** for training and **detects phishing** through email filters and website URL analysis.

> **Educational Use Only** — This tool is designed for cybersecurity learning, authorized security awareness training, and defensive research. Never use simulated phishing content for unauthorized attacks.

---

## Project Overview

| Component | Description |
|-----------|-------------|
| **Phishing Simulator** | Generates realistic phishing email scenarios (credential harvest, fake invoice, account suspension, prize scam, tech support) |
| **Email Detector** | Rule-based email filter detecting urgency language, typosquatting, suspicious URLs, display name mismatches |
| **URL Detector** | Website detection via typosquatting, suspicious TLDs, homograph attacks, IP-based URLs, DNS checks |
| **Reporting** | JSON + HTML reports with detection confidence scores and triggered rules |

### Skills Demonstrated

- Phishing attack techniques and social engineering patterns
- Email security filtering and heuristic analysis
- Website / malicious URL detection
- Security awareness training workflow
- Python application development and CLI tooling

---

## Project Structure

```
Project_1/
├── main.py                          # CLI entry point
├── requirements.txt
├── config/
│   └── settings.yaml                # Detection thresholds & rules
├── src/
│   ├── simulator/                   # Phishing simulation engine
│   │   ├── scenario_generator.py
│   │   └── email_simulator.py
│   ├── detector/                    # Detection modules
│   │   ├── email_detector.py
│   │   ├── url_detector.py
│   │   └── rules.py
│   ├── report/
│   │   └── reporter.py
│   └── utils/
│       └── helpers.py
├── data/
│   ├── sample_legitimate_emails.json
│   └── sample_phishing_urls.json
├── tests/
│   ├── test_email_detector.py
│   └── test_url_detector.py
├── reports/                         # Generated HTML/JSON reports
└── docs/
    └── LEARNING_GUIDE.md
```

---

## Installation

### Prerequisites

- Python 3.9 or higher
- pip

### Setup

```bash
# Clone or navigate to project directory
cd Project_1

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Full Demo (Recommended First Run)

Runs simulation → email detection → URL detection → report generation:

```bash
python main.py demo
```

### Simulate Phishing Emails

```bash
# Generate 1 random scenario
python main.py simulate

# Generate 5 scenarios
python main.py simulate --count 5

# Specific scenario type
python main.py simulate --scenario credential_harvest
```

Available scenarios: `credential_harvest`, `fake_invoice`, `account_suspension`, `prize_scam`, `tech_support`

```bash
python main.py scenarios
```

### Detect Phishing in Emails

```bash
# From simulated campaign file
python main.py detect-email --file data/simulated/campaign.json

# Manual input
python main.py detect-email \
  --subject "URGENT: Verify Account" \
  --sender "security@paypa1-secure.com" \
  --display "PayPal Security" \
  --body "Dear User, verify at http://paypa1-secure.com/login"
```

### Detect Malicious URLs

```bash
python main.py detect-url --urls http://paypa1-secure.com/login http://microsft-login.com

python main.py detect-url --file data/sample_phishing_urls.json
```

---

## Detection Rules

### Email Phishing Detection

| Rule | Description |
|------|-------------|
| Suspicious sender domain | Typosquatted or lookalike domains |
| Display name mismatch | Brand name in display but not in email domain |
| Urgency keywords | "Act now", "verify account", "suspended" |
| Suspicious URLs | Malicious links in email body |
| Generic greeting | "Dear User" instead of your name |
| Threat language | Account termination, virus warnings |
| Excessive caps | ALL CAPS subject lines |
| Reply-to mismatch | Reply-to domain differs from sender |

### URL / Website Detection

| Rule | Description |
|------|-------------|
| Typosquatting | Domain mimics legitimate brands (paypa1, microsft) |
| Suspicious TLD | .xyz, .top, .club, .tk domains |
| IP address URL | Direct IP instead of domain name |
| Homograph attack | Unicode lookalike characters |
| Missing HTTPS | Non-encrypted connection |
| @ symbol redirect | URL obfuscation tricks |
| Suspicious keywords | login, verify, secure in untrusted domains |

---

## Running Tests

```bash
python -m pytest tests/ -v
```

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║     PHISHING ATTACK SIMULATION & DETECTION SYSTEM            ║
╚══════════════════════════════════════════════════════════════╝

[SIMULATION MODE] Generating phishing scenarios...

============================================================
  PHISHING SIMULATION - Credential Harvesting
============================================================
From:    Microsoft Account Team <account@microsft-login.com>
Subject: Security Alert: Unusual Sign-in Detected
------------------------------------------------------------
Dear User,
We detected unusual activity on your account...
------------------------------------------------------------
RED FLAGS TO IDENTIFY:
  1. Urgency and threat of account suspension
  2. Spoofed sender domain (typosquatting)
  ...
```

---

## Web App (Local)

Run the web UI locally:

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

Opens at `http://localhost:8501`

---

## Deploy Online (Streamlit Cloud — Free)

1. Go to [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub
2. Click **New app**
3. Select repository: `Shikha-Upadhyay13/Phishing_Attack_Simulation_and_Detection`
4. Set **Main file path** to: `streamlit_app.py`
5. Click **Deploy**

Your live app URL will look like:
`https://phishing-attack-simulation-and-detection.streamlit.app`

Share this link on LinkedIn and in your internship submission email.

---

## Publishing on GitHub

1. Create a new repository on GitHub (e.g., `phishing-simulation-detection`)
2. Initialize and push:

```bash
git init
git add .
git commit -m "Add phishing simulation and detection system"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/phishing-simulation-detection.git
git push -u origin main
```

3. Add a screenshot of `python main.py demo` output to your README
4. Share the GitHub link on LinkedIn with a brief project description

---

## Internship Submission

After completing this project and one additional project:

1. Publish both on **GitHub** and/or **LinkedIn**
2. Email the project links along with your Offer Letter to:
   **vaishali@codectechnologies.in**

---

## Author

**Shikha** — CodeCT Technologies Internship Project

## License

MIT License — For educational and authorized security testing purposes only.
