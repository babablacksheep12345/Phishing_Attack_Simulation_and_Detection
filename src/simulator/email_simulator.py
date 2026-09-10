"""Email phishing simulation engine for security awareness."""

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .scenario_generator import PhishingScenario, ScenarioGenerator


class EmailSimulator:
    """Simulates phishing emails for training and testing detection systems."""

    def __init__(self, output_dir: str | Path = "data/simulated"):
        self.generator = ScenarioGenerator()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def simulate_single(self, scenario_key: str | None = None) -> dict:
        """Simulate one phishing email and return structured data."""
        scenario = self.generator.generate(scenario_key)
        return self._scenario_to_email(scenario)

    def simulate_campaign(self, count: int = 5) -> list[dict]:
        """Simulate a phishing awareness campaign with multiple emails."""
        scenarios = self.generator.generate_batch(count)
        return [self._scenario_to_email(s) for s in scenarios]

    def _scenario_to_email(self, scenario: PhishingScenario) -> dict:
        """Convert scenario to email-like structure."""
        return {
            "simulation_id": f"SIM-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{scenario.category[:3].upper()}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_simulated": True,
            "ground_truth": "phishing",
            "scenario": scenario.name,
            "category": scenario.category,
            "difficulty": scenario.difficulty,
            "email": {
                "from_display": scenario.sender_display,
                "from_address": scenario.sender_email,
                "subject": scenario.subject,
                "body": scenario.body,
                "urls": [scenario.malicious_url],
            },
            "red_flags": scenario.red_flags,
            "training_notes": (
                "This is a SIMULATED phishing email for security awareness training only. "
                "Do NOT use these templates for unauthorized phishing attacks."
            ),
        }

    def save_campaign(self, emails: list[dict], filename: str = "campaign.json") -> Path:
        """Save simulated campaign to JSON file."""
        filepath = self.output_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(emails, f, indent=2)
        return filepath

    def format_email_display(self, email_data: dict) -> str:
        """Format simulated email for terminal display."""
        email = email_data["email"]
        lines = [
            "=" * 60,
            f"  PHISHING SIMULATION - {email_data['scenario']}",
            "=" * 60,
            f"From:    {email['from_display']} <{email['from_address']}>",
            f"Subject: {email['subject']}",
            "-" * 60,
            email["body"],
            "-" * 60,
            "RED FLAGS TO IDENTIFY:",
        ]
        for i, flag in enumerate(email_data["red_flags"], 1):
            lines.append(f"  {i}. {flag}")
        lines.append("=" * 60)
        return "\n".join(lines)
