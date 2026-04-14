import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timezone

class PRSecurityChecker:
    def __init__(self, pr_base: str, pr_head: str, target_dir: str = "."):
        self.pr_base = pr_base
        self.pr_head = pr_head
        self.target_dir = Path(target_dir)
        self.findings: List[Dict] = []

    def get_changed_files(self) -> List[str]:
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", self.pr_base, self.pr_head],
                capture_output=True, text=True, cwd=self.target_dir
            )
            if result.returncode != 0:
                print(f"Warning: Git diff failed: {result.stderr}", file=sys.stderr)
                return []
            return [f.strip() for f in result.stdout.split('\n') if f.strip()]
        except Exception as e:
            print(f"Warning: Error getting changed files: {e}", file=sys.stderr)
            return []

    def check_file(self, filepath: Path) -> List[Dict]:
        findings = []

        if not filepath.exists() or filepath.suffix != '.py':
            return findings

        try:
            content = filepath.read_text()
            lines = content.split('\n')

            secret_patterns = [
                (r'(password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded password"),
                (r'(api_key|apikey|api-key)\s*=\s*["\'][^"\']+["\']', "Hardcoded API key"),
                (r'(secret|token)\s*=\s*["\'][^"\']{16,}["\']', "Hardcoded secret/token"),
                (r'AWS_[A-Z_]+\s*=\s*["\'][^"\']+["\']', "Hardcoded AWS credential"),
            ]

            for i, line in enumerate(lines, 1):
                for pattern, desc in secret_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "owasp_id": "A02:2021",
                            "title": desc,
                            "severity": "HIGH",
                            "description": "Potential hardcoded secret in code",
                            "file": str(filepath),
                            "line": i,
                            "code_snippet": line.strip()[:100],
                            "remediation": "Use environment variables or GitHub Secrets"
                        })

            # A03: Injection risks
            injection_patterns = [
                (r'execute\s*\(\s*f["\'].*\{.*\}.*["\']', "SQL injection with f-string"),
                (r'os\.system\s*\(\s*f["\']', "Command injection with f-string"),
                (r'eval\s*\(\s*.*input\s*\(', "Eval with user input"),
            ]

            for i, line in enumerate(lines, 1):
                for pattern, desc in injection_patterns:
                    if re.search(pattern, line):
                        findings.append({
                            "owasp_id": "A03:2021",
                            "title": desc,
                            "severity": "CRITICAL",
                            "description": "Potential injection vulnerability",
                            "file": str(filepath),
                            "line": i,
                            "code_snippet": line.strip()[:100],
                            "remediation": "Use parameterized queries; avoid eval/exec with user input"
                        })

            # A07: Weak auth patterns
            if filepath.name in ["web_app.py", "api.py", "auth.py"]:
                for i, line in enumerate(lines, 1):
                    if re.search(r'password\s*==\s*["\'][^"\']+["\']', line, re.IGNORECASE):
                        findings.append({
                            "owasp_id": "A07:2021",
                            "title": "Weak password comparison",
                            "severity": "HIGH",
                            "description": "Plain text password comparison detected",
                            "file": str(filepath),
                            "line": i,
                            "code_snippet": line.strip()[:100],
                            "remediation": "Use bcrypt/argon2 for password hashing"
                        })

        except Exception as e:
            print(f"Warning: Error checking {filepath}: {e}", file=sys.stderr)

        return findings

    def run(self) -> Dict:
        print(f"Scanning PR changes: {self.pr_base} -> {self.pr_head}")

        changed_files = self.get_changed_files()
        print(f"Found {len(changed_files)} changed file(s)")

        for filepath_str in changed_files:
            filepath = self.target_dir / filepath_str
            if filepath.exists():
                file_findings = self.check_file(filepath)
                self.findings.extend(file_findings)
                if file_findings:
                    print(f"  Warning: {filepath}: {len(file_findings)} issue(s)")

        summary = {
            "total": len(self.findings),
            "critical": sum(1 for f in self.findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in self.findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in self.findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in self.findings if f["severity"] == "LOW"),
        }

        print(f"Scan complete: {summary['total']} findings")

        return {
            "pr_base": self.pr_base,
            "pr_head": self.pr_head,
            "changed_files": changed_files,
            "summary": summary,
            "findings": self.findings,
            "scanned_at": datetime.now(timezone.utc).isoformat()
        }

def main():
    parser = argparse.ArgumentParser(description="PR Security Checker")
    parser.add_argument("--pr-base", required=True, help="Base commit SHA")
    parser.add_argument("--pr-head", required=True, help="Head commit SHA")
    parser.add_argument("--target", default=".", help="Target directory")
    parser.add_argument("--output", help="Output JSON file")

    args = parser.parse_args()

    checker = PRSecurityChecker(args.pr_base, args.pr_head, args.target)
    results = checker.run()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))

    print(f"::set-output name=critical_count::{results['summary']['critical']}")
    print(f"::set-output name=high_count::{results['summary']['high']}")

if __name__ == "__main__":
    main()