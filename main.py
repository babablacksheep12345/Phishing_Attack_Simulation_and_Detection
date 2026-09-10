#!/usr/bin/env python3
"""
Phishing Attack Simulation and Detection System
==================================================
A security awareness tool that simulates phishing attacks and detects them
using email filters and fake website detection.

FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY.
"""

import argparse
import json
import sys
from pathlib import Path

from colorama import Fore, Style, init

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.detector.email_detector import EmailPhishingDetector
from src.detector.url_detector import URLPhishingDetector
from src.report.reporter import ReportGenerator
from src.simulator.email_simulator import EmailSimulator
from src.utils.helpers import load_config

init(autoreset=True)


def print_banner():
    banner = f"""
{Fore.CYAN}{'=' * 62}
     PHISHING ATTACK SIMULATION & DETECTION SYSTEM
     Security Awareness | Email Filters | URL Detection
{'=' * 62}{Style.RESET_ALL}
"""
    print(banner)


def cmd_simulate(args, config):
    """Run phishing email simulation."""
    simulator = EmailSimulator()
    print(f"\n{Fore.YELLOW}[SIMULATION MODE]{Style.RESET_ALL} Generating phishing scenarios...\n")

    if args.scenario:
        emails = [simulator.simulate_single(args.scenario)]
    else:
        emails = simulator.simulate_campaign(args.count)

    for email_data in emails:
        print(simulator.format_email_display(email_data))
        print()

    filepath = simulator.save_campaign(emails)
    print(f"{Fore.GREEN}[OK] Saved {len(emails)} simulated email(s) to: {filepath}{Style.RESET_ALL}")
    return emails


def cmd_detect_email(args, config):
    """Detect phishing in an email."""
    detector = EmailPhishingDetector(config)

    if args.file:
        with open(args.file, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            emails = data
        elif "email" in data:
            emails = [data]
        else:
            emails = [data]
    else:
        emails = [{
            "subject": args.subject or "",
            "body": args.body or "",
            "from_address": args.sender or "",
            "from_display": args.display or "",
        }]

    print(f"\n{Fore.YELLOW}[EMAIL DETECTION]{Style.RESET_ALL} Analyzing {len(emails)} email(s)...\n")

    results = []
    for item in emails:
        email = item.get("email", item)
        result = detector.analyze_email_dict(email)
        results.append({
            "subject": email.get("subject", "N/A"),
            "is_phishing": result.is_phishing,
            "confidence": result.confidence,
            "risk_level": result.risk_level,
            "triggered_rules": result.triggered_rules,
            "details": result.details,
        })

        verdict = f"{Fore.RED}PHISHING DETECTED" if result.is_phishing else f"{Fore.GREEN}LEGITIMATE"
        print(f"  Subject: {email.get('subject', 'N/A')}")
        print(f"  Verdict: {verdict}{Style.RESET_ALL}")
        print(f"  Confidence: {result.confidence:.1%} | Risk: {result.risk_level}")
        if result.triggered_rules:
            print(f"  Rules: {', '.join(result.triggered_rules)}")
        print()

    return results


def cmd_detect_url(args, config):
    """Detect fake/phishing URLs."""
    detector = URLPhishingDetector(config)
    urls = args.urls or []

    if args.file:
        with open(args.file, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            urls.extend(data if isinstance(data[0], str) else [u.get("url", "") for u in data])
        elif "urls" in data:
            urls.extend(data["urls"])

    print(f"\n{Fore.YELLOW}[URL DETECTION]{Style.RESET_ALL} Analyzing {len(urls)} URL(s)...\n")

    results = detector.analyze_batch(urls)
    for r in results:
        verdict = f"{Fore.RED}MALICIOUS" if r["is_phishing"] else f"{Fore.GREEN}SAFE"
        print(f"  URL: {r['url']}")
        print(f"  Verdict: {verdict}{Style.RESET_ALL}")
        print(f"  Confidence: {r['confidence']:.1%} | Risk: {r['risk_level']}")
        if r["triggered_rules"]:
            print(f"  Rules: {', '.join(r['triggered_rules'])}")
        print()

    return results


def cmd_full_demo(args, config):
    """Run full simulation + detection demo."""
    print(f"\n{Fore.CYAN}--- FULL DEMONSTRATION: Simulate -> Detect -> Report ---{Style.RESET_ALL}\n")

    # Step 1: Simulate
    simulator = EmailSimulator()
    emails = simulator.simulate_campaign(args.count)
    print(f"{Fore.YELLOW}Step 1:{Style.RESET_ALL} Generated {len(emails)} phishing scenarios\n")

    for email_data in emails:
        print(simulator.format_email_display(email_data))

    # Step 2: Detect emails
    email_detector = EmailPhishingDetector(config)
    url_detector = URLPhishingDetector(config)

    email_results = []
    all_urls = []

    print(f"\n{Fore.YELLOW}Step 2:{Style.RESET_ALL} Running detection on simulated emails...\n")

    for email_data in emails:
        email = email_data["email"]
        result = email_detector.analyze_email_dict(email)
        email_results.append({
            "subject": email["subject"],
            "is_phishing": result.is_phishing,
            "confidence": result.confidence,
            "risk_level": result.risk_level,
            "triggered_rules": result.triggered_rules,
            "details": result.details,
        })
        all_urls.extend(email.get("urls", []))

    detected = sum(1 for r in email_results if r["is_phishing"])
    print(f"  Email Detection: {detected}/{len(email_results)} correctly flagged as phishing\n")

    # Step 3: Detect URLs
    print(f"{Fore.YELLOW}Step 3:{Style.RESET_ALL} Analyzing malicious URLs...\n")
    url_results = url_detector.analyze_batch(all_urls)
    url_detected = sum(1 for r in url_results if r["is_phishing"])
    print(f"  URL Detection: {url_detected}/{len(url_results)} correctly flagged as malicious\n")

    # Step 4: Generate report
    reporter = ReportGenerator()
    report_path = reporter.generate_detection_report(
        email_results, url_results,
        campaign_info={"simulated_count": len(emails), "mode": "full_demo"},
    )
    print(f"{Fore.GREEN}[OK] Report generated: {report_path}{Style.RESET_ALL}")

    # Also test with legitimate samples
    print(f"\n{Fore.YELLOW}Step 4:{Style.RESET_ALL} Testing with legitimate email samples...\n")
    legit_path = Path("data/sample_legitimate_emails.json")
    if legit_path.exists():
        with open(legit_path, encoding="utf-8") as f:
            legit_emails = json.load(f)
        legit_detected = 0
        for email in legit_emails:
            result = email_detector.analyze_email_dict(email)
            status = "FALSE POSITIVE!" if result.is_phishing else "OK"
            color = Fore.RED if result.is_phishing else Fore.GREEN
            print(f"  {color}[{status}]{Style.RESET_ALL} {email.get('subject', 'N/A')}")
            if result.is_phishing:
                legit_detected += 1
        print(f"\n  Legitimate emails falsely flagged: {legit_detected}/{len(legit_emails)}")

    print(f"\n{Fore.GREEN}--- Demo Complete ---{Style.RESET_ALL}")


def cmd_list_scenarios(args, config):
    """List available simulation scenarios."""
    from src.simulator.scenario_generator import ScenarioGenerator
    gen = ScenarioGenerator()
    print(f"\n{Fore.CYAN}Available Phishing Scenarios:{Style.RESET_ALL}\n")
    for key in gen.list_scenarios():
        scenario = gen.generate(key)
        print(f"  • {key}: {scenario.name}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Attack Simulation and Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py demo                    Full simulation + detection demo
  python main.py simulate --count 3      Generate 3 phishing scenarios
  python main.py detect-email --file data/simulated/campaign.json
  python main.py detect-url --urls http://paypa1-secure.com/login
  python main.py scenarios               List available scenarios
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Demo command
    demo_parser = subparsers.add_parser("demo", help="Full simulation + detection demo")
    demo_parser.add_argument("--count", type=int, default=5, help="Number of scenarios")

    # Simulate command
    sim_parser = subparsers.add_parser("simulate", help="Simulate phishing emails")
    sim_parser.add_argument("--count", type=int, default=1, help="Number of emails")
    sim_parser.add_argument("--scenario", type=str, help="Specific scenario key")

    # Detect email command
    email_parser = subparsers.add_parser("detect-email", help="Detect phishing in emails")
    email_parser.add_argument("--file", type=str, help="JSON file with email(s)")
    email_parser.add_argument("--subject", type=str, help="Email subject")
    email_parser.add_argument("--body", type=str, help="Email body")
    email_parser.add_argument("--sender", type=str, help="Sender email address")
    email_parser.add_argument("--display", type=str, help="Sender display name")

    # Detect URL command
    url_parser = subparsers.add_parser("detect-url", help="Detect fake/phishing URLs")
    url_parser.add_argument("--urls", nargs="+", help="URLs to analyze")
    url_parser.add_argument("--file", type=str, help="JSON file with URLs")

    # List scenarios
    subparsers.add_parser("scenarios", help="List available simulation scenarios")

    args = parser.parse_args()
    config = load_config()
    print_banner()

    if args.command == "demo":
        cmd_full_demo(args, config)
    elif args.command == "simulate":
        cmd_simulate(args, config)
    elif args.command == "detect-email":
        cmd_detect_email(args, config)
    elif args.command == "detect-url":
        cmd_detect_url(args, config)
    elif args.command == "scenarios":
        cmd_list_scenarios(args, config)
    else:
        parser.print_help()
        print(f"\n{Fore.CYAN}Tip: Run 'python main.py demo' for a full demonstration!{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
