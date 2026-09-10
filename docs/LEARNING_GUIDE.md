# Learning Guide: Phishing Simulation & Detection

## 1. What is Phishing?

Phishing is a social engineering attack where attackers impersonate trusted entities (banks, tech companies, colleagues) to trick victims into:

- Revealing credentials (usernames, passwords)
- Clicking malicious links
- Downloading malware
- Making fraudulent payments

## 2. Common Phishing Techniques

### Email Phishing
- **Spoofed sender addresses**: `security@paypa1-secure.com` mimics PayPal
- **Urgency tactics**: "Your account will be closed in 24 hours"
- **Generic greetings**: "Dear User" instead of your actual name
- **Malicious links**: Hidden URLs that redirect to fake login pages

### Website Spoofing
- **Typosquatting**: `microsft-login.com`, `g00gle-security.com`
- **Homograph attacks**: Using Unicode characters that look like ASCII (e.g., Cyrillic 'а' vs Latin 'a')
- **IP-based URLs**: `http://192.168.1.1/login` instead of a domain name
- **Suspicious TLDs**: `.xyz`, `.top`, `.club` often used for malicious sites

## 3. How Our Detection System Works

### Email Filter Pipeline

```
Email Input → Parse Headers & Body → Apply Rules → Weighted Score → Verdict
```

Each rule contributes a weighted score. If total score ≥ threshold (0.5), email is flagged as phishing.

### URL Analysis Pipeline

```
URL Input → Parse Domain → Check Typosquatting → Check TLD → DNS Lookup → Verdict
```

## 4. Hands-On Exercises

### Exercise 1: Identify Red Flags
Run `python main.py simulate` and for each email, try to identify all red flags BEFORE looking at the answer.

### Exercise 2: Test Detection Accuracy
Run `python main.py demo` and note how many simulated emails are correctly detected.

### Exercise 3: Create Your Own Test Case
Add a new email to `data/sample_legitimate_emails.json` and run detection on it.

### Exercise 4: Analyze Real-World Patterns
Research recent phishing campaigns (e.g., from APWG reports) and compare their techniques with our simulation scenarios.

## 5. Key Takeaways

1. **Always verify the sender** — Check the actual email address, not just the display name
2. **Hover before clicking** — Inspect URLs before clicking links
3. **Be skeptical of urgency** — Legitimate companies rarely threaten immediate account closure
4. **Use multi-factor authentication** — Even if credentials are stolen, MFA provides protection
5. **Report suspicious emails** — Use your organization's reporting mechanism

## 6. Further Reading

- [APWG Phishing Activity Trends Report](https://apwg.org/)
- [CISA Phishing Guidance](https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks)
- [OWASP Social Engineering](https://owasp.org/www-community/attacks/Social_Engineering)
