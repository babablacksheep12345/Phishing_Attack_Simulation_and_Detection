"""Generate analysis reports for phishing detection results."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ReportGenerator:
    """Creates JSON and HTML reports from detection results."""

    def __init__(self, output_dir: str | Path = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_detection_report(
        self,
        email_results: list[dict],
        url_results: list[dict],
        campaign_info: dict | None = None,
    ) -> Path:
        """Generate comprehensive detection report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report = {
            "report_type": "phishing_detection_analysis",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_emails_analyzed": len(email_results),
                "phishing_emails_detected": sum(1 for r in email_results if r.get("is_phishing")),
                "total_urls_analyzed": len(url_results),
                "malicious_urls_detected": sum(1 for r in url_results if r.get("is_phishing")),
            },
            "email_analysis": email_results,
            "url_analysis": url_results,
            "campaign_info": campaign_info,
        }

        json_path = self.output_dir / f"detection_report_{timestamp}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        html_path = self.output_dir / f"detection_report_{timestamp}.html"
        html_path.write_text(self._to_html(report), encoding="utf-8")

        return html_path

    def _to_html(self, report: dict[str, Any]) -> str:
        summary = report["summary"]
        email_rows = ""
        for r in report["email_analysis"]:
            status = "PHISHING" if r.get("is_phishing") else "LEGITIMATE"
            color = "#dc3545" if r.get("is_phishing") else "#28a745"
            email_rows += f"""
            <tr>
                <td>{r.get('subject', 'N/A')}</td>
                <td style="color:{color};font-weight:bold">{status}</td>
                <td>{r.get('confidence', 0):.1%}</td>
                <td>{r.get('risk_level', 'N/A')}</td>
                <td>{', '.join(r.get('triggered_rules', []))}</td>
            </tr>"""

        url_rows = ""
        for r in report["url_analysis"]:
            status = "MALICIOUS" if r.get("is_phishing") else "SAFE"
            color = "#dc3545" if r.get("is_phishing") else "#28a745"
            url_rows += f"""
            <tr>
                <td style="word-break:break-all">{r.get('url', 'N/A')}</td>
                <td style="color:{color};font-weight:bold">{status}</td>
                <td>{r.get('confidence', 0):.1%}</td>
                <td>{r.get('risk_level', 'N/A')}</td>
                <td>{', '.join(r.get('triggered_rules', []))}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Phishing Detection Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1100px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .card {{ background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; }}
        .card h3 {{ margin: 0; color: #007bff; font-size: 2em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
        th {{ background: #007bff; color: white; }}
        tr:nth-child(even) {{ background: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Phishing Detection Report</h1>
        <p>Generated: {report['generated_at']}</p>
        <div class="summary">
            <div class="card"><h3>{summary['total_emails_analyzed']}</h3><p>Emails Analyzed</p></div>
            <div class="card"><h3>{summary['phishing_emails_detected']}</h3><p>Phishing Detected</p></div>
            <div class="card"><h3>{summary['total_urls_analyzed']}</h3><p>URLs Analyzed</p></div>
            <div class="card"><h3>{summary['malicious_urls_detected']}</h3><p>Malicious URLs</p></div>
        </div>
        <h2>Email Analysis</h2>
        <table>
            <tr><th>Subject</th><th>Verdict</th><th>Confidence</th><th>Risk</th><th>Rules Triggered</th></tr>
            {email_rows}
        </table>
        <h2>URL Analysis</h2>
        <table>
            <tr><th>URL</th><th>Verdict</th><th>Confidence</th><th>Risk</th><th>Rules Triggered</th></tr>
            {url_rows}
        </table>
    </div>
</body>
</html>"""
