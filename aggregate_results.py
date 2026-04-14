import argparse
import json
from pathlib import Path

def load_json(filepath: str) -> dict:
    if not Path(filepath).exists():
        return {}
    with open(filepath, "r") as f:
        return json.load(f)

def aggregate(bandit_file: str, safety_file: str, custom_file: str) -> dict:
    findings = []

    bandit = load_json(bandit_file)
    if isinstance(bandit, list):
        for issue in bandit:
            findings.append({
                "source": "bandit",
                "owasp_id": "A03:2021",
                "title": issue.get("test_name", "Security issue"),
                "severity": issue.get("issue_severity", "MEDIUM").upper(),
                "description": issue.get("issue_text", ""),
                "file": issue.get("filename", ""),
                "line": issue.get("line_number"),
                "remediation": issue.get("more_info", "")
            })

    safety = load_json(safety_file)
    if isinstance(safety, list):
        for vuln in safety:
            findings.append({
                "source": "safety",
                "owasp_id": "A06:2021",
                "title": f"Vulnerable package: {vuln.get('package_name')}",
                "severity": "HIGH",
                "description": vuln.get("advisory", ""),
                "file": "requirements.txt",
                "remediation": f"Upgrade to {vuln.get('vuln_spec', 'latest')}"
            })

    custom = load_json(custom_file)
    if "findings" in custom:
        findings.extend(custom["findings"])

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 5))

    summary = {
        "total": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW"),
    }

    return {
        "summary": summary,
        "findings": findings,
        "sources": {
            "bandit": bool(bandit),
            "safety": bool(safety),
            "custom": bool(custom)
        }
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bandit", default="bandit_report.json")
    parser.add_argument("--safety", default="safety_report.json")
    parser.add_argument("--custom", default="scan_results.json")
    parser.add_argument("--output", required=True)

    args = parser.parse_args()

    result = aggregate(args.bandit, args.safety, args.custom)

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Aggregated report saved to {args.output}")
    print(f"Summary: {result['summary']}")


if __name__ == "__main__":
    main()