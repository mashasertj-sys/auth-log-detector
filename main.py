import argparse
import re
import json
import yaml
import os
import subprocess
import platform
import sys
import hashlib
import csv
from collections import defaultdict
from datetime import datetime, timezone

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    console = None
    RICH_AVAILABLE = False

HISTORY_FILE = "alerts_history.json"
ALERTS_OUTPUT_FILE = "security_alerts.json"
REPORTS_DIR = "reports"
TABLE_TXT_FILE = os.path.join(REPORTS_DIR, "alert_table.txt")
TABLE_CSV_FILE = os.path.join(REPORTS_DIR, "alert_table.csv")
TABLE_HTML_FILE = os.path.join(REPORTS_DIR, "alert_table.html")
NOTIFICATIONS_LOG = os.path.join(REPORTS_DIR, "notifications.log")


def safe_print(msg: str, style: str = None):
    if console and style:
        console.print(msg, style=style)
    else:
        print(msg)

def ensure_reports_dir():
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)

def load_history() -> dict:
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"alerts": [], "last_run": None}
    return {"alerts": [], "last_run": None}


def save_history(history: dict):
    history["last_run"] = datetime.now(timezone.utc).isoformat()
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=4, ensure_ascii=False)


def generate_alert_id(alert: dict) -> str:
    unique_string = f"{alert['rule']}:{alert['indicator']}:{alert['technique']}"
    return hashlib.md5(unique_string.encode()).hexdigest()[:8]


def is_new_alert(alert: dict, history: dict) -> bool:
    alert_id = generate_alert_id(alert)
    existing_ids = [a.get("alert_id") for a in history.get("alerts", [])]
    return alert_id not in existing_ids


def load_rules(path: str) -> list:
    if not os.path.exists(path):
        safe_print(f"[ERROR] Rules file not found: {path}", "bold red")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f)
    if not isinstance(rules, list):
        safe_print("[ERROR] Invalid rules format: expected a YAML list", "bold red")
        sys.exit(1)
    return rules


def parse_logs(path: str) -> list[str]:
    if not os.path.exists(path):
        safe_print(f"[ERROR] Log file not found: {path}", "bold red")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def detect(logs: list[str], rules: list[dict]) -> list[dict]:
    alerts = []
    for rule in rules:
        ip_counts = defaultdict(int)
        pattern = rule.get("pattern", "")
        threshold = rule.get("threshold", 1)

        for line in logs:
            match = re.search(pattern, line)
            if match:
                indicator = match.group(1) if match.lastindex and match.group(1) else "system_event"
                ip_counts[indicator] += 1

        for indicator, count in ip_counts.items():
            if count >= threshold:
                alert = {
                    "rule": rule["name"],
                    "severity": rule.get("severity", "INFO"),
                    "technique": rule.get("technique", "N/A"),
                    "indicator": indicator,
                    "count": count,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                }
                alert["alert_id"] = generate_alert_id(alert)
                alerts.append(alert)
    return alerts


def send_desktop_alert(alert: dict, is_new: bool = True):
    if platform.system() != "Darwin":
        safe_print("[WARNING] Desktop notifications currently supported only on macOS.", "yellow")
        return

    severity_prefix = "[CRITICAL]" if alert["severity"] == "HIGH" else "[WARNING]"
    new_badge = "[NEW] " if is_new else "[EXISTING] "
    title = f'{new_badge}{severity_prefix} {alert["rule"]}'
    message = f'IP: {alert["indicator"]} | Count: {alert["count"]} | {alert["technique"]}'

    title = title.replace('"', '\\"')
    message = message.replace('"', '\\"')
    script = f'display notification "{message}" with title "{title}"'

    try:
        subprocess.run(["osascript", "-e", script], check=False, capture_output=True)
    except Exception as e:
        safe_print(f"[ERROR] Notification failed: {e}", "red")


def log_notification(alert: dict, is_new: bool):
    ensure_reports_dir()
    timestamp = datetime.now(timezone.utc).isoformat()
    status = "NEW" if is_new else "EXISTING"

    log_entry = f"[{timestamp}] [{status}] {alert['rule']} | Severity: {alert['severity']} | IP: {alert['indicator']} | Count: {alert['count']} | Technique: {alert['technique']}\n"

    with open(NOTIFICATIONS_LOG, "a", encoding="utf-8") as f:
        f.write(log_entry)


def print_table(alerts: list[dict], new_count: int):
    if not alerts:
        safe_print("Info: No alerts detected.", "green")
        return

    table = Table(title=f"Security Alerts (New: {new_count}/{len(alerts)})", show_lines=True, expand=True)
    table.add_column("Rule", style="cyan", no_wrap=True)
    table.add_column("Severity", style="bold")
    table.add_column("IP", style="magenta")
    table.add_column("Count", justify="right")
    table.add_column("Status", style="bold")
    table.add_column("Technique", style="green")

    for a in alerts:
        sev_style = "bold red" if a["severity"] == "HIGH" else "bold yellow" if a[
                                                                                    "severity"] == "MEDIUM" else "bold green"
        status = "[NEW]" if a.get("is_new", False) else "[EXISTING]"
        status_style = "bold green" if a.get("is_new", False) else "dim"

        table.add_row(
            a["rule"],
            f"[{sev_style}]{a['severity']}[/{sev_style}]",
            a["indicator"],
            str(a["count"]),
            f"[{status_style}]{status}[/{status_style}]",
            a["technique"]
        )

    if console:
        console.print(table)
    else:
        print(f"{'Rule':<20} | {'Severity':<10} | {'IP':<16} | {'Count':<6} | {'Status':<12} | {'Technique'}")
        print("-" * 100)
        for a in alerts:
            status = "[NEW]" if a.get("is_new", False) else "[EXISTING]"
            print(
                f"{a['rule']:<20} | {a['severity']:<10} | {a['indicator']:<16} | {a['count']:<6} | {status:<12} | {a['technique']}")


def save_table_to_txt(alerts: list[dict], new_count: int):
    ensure_reports_dir()

    with open(TABLE_TXT_FILE, "w", encoding="utf-8") as f:
        f.write("=" * 100 + "\n")
        f.write(f"SECURITY ALERTS REPORT\n")
        f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"Total: {len(alerts)} alerts ({new_count} new, {len(alerts) - new_count} existing)\n")
        f.write("=" * 100 + "\n\n")

        f.write(f"{'Rule':<20} | {'Severity':<10} | {'IP':<16} | {'Count':<6} | {'Status':<12} | {'Technique'}\n")
        f.write("-" * 100 + "\n")
        for a in alerts:
            status = "[NEW]" if a.get("is_new", False) else "[EXISTING]"
            f.write(
                f"{a['rule']:<20} | {a['severity']:<10} | {a['indicator']:<16} | {a['count']:<6} | {status:<12} | {a['technique']}\n")

        f.write("\n" + "=" * 100 + "\n")
        f.write(f"[INFO] Report saved to {TABLE_TXT_FILE}\n")

    safe_print(f"[SAVE] Table saved to {TABLE_TXT_FILE}", "green")


def save_table_to_csv(alerts: list[dict]):
    ensure_reports_dir()

    with open(TABLE_CSV_FILE, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Rule", "Severity", "IP", "Count", "Status", "Technique", "Timestamp", "Alert_ID"])
        for a in alerts:
            status = "NEW" if a.get("is_new", False) else "EXISTING"
            writer.writerow([
                a["rule"],
                a["severity"],
                a["indicator"],
                a["count"],
                status,
                a["technique"],
                a["timestamp"],
                a["alert_id"]
            ])

    safe_print(f"[SAVE] Table saved to {TABLE_CSV_FILE}", "green")


def save_table_to_html(alerts: list[dict], new_count: int):
    """Сохраняет таблицу в HTML формат"""
    ensure_reports_dir()

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Alerts Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #1e1e1e; color: #fff; }}
        h1 {{ color: #4CAF50; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #444; padding: 12px; text-align: left; }}
        th {{ background-color: #333; color: #4CAF50; }}
        tr:nth-child(even) {{ background-color: #2a2a2a; }}
        tr:hover {{ background-color: #3a3a3a; }}
        .new {{ color: #4CAF50; font-weight: bold; }}
        .existing {{ color: #888; }}
        .high {{ color: #f44336; font-weight: bold; }}
        .medium {{ color: #ff9800; }}
        .low {{ color: #2196F3; }}
        .stats {{ background-color: #333; padding: 10px; border-radius: 5px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1> Security Alerts Report</h1>
    <div class="stats">
        <strong>Generated:</strong> {datetime.now(timezone.utc).isoformat()}<br>
        <strong>Total Alerts:</strong> {len(alerts)} ({new_count} new, {len(alerts) - new_count} existing)
    </div>
    <table>
        <thead>
            <tr>
                <th>Rule</th>
                <th>Severity</th>
                <th>IP</th>
                <th>Count</th>
                <th>Status</th>
                <th>Technique</th>
            </tr>
        </thead>
        <tbody>
"""
    for a in alerts:
        status = "NEW" if a.get("is_new", False) else "EXISTING"
        status_class = "new" if a.get("is_new", False) else "existing"
        severity_class = "high" if a["severity"] == "HIGH" else "medium" if a["severity"] == "MEDIUM" else "low"

        html += f"""            <tr>
                <td>{a['rule']}</td>
                <td class="{severity_class}">{a['severity']}</td>
                <td>{a['indicator']}</td>
                <td>{a['count']}</td>
                <td class="{status_class}">{status}</td>
                <td>{a['technique']}</td>
            </tr>
"""

    html += """        </tbody>
    </table>
</body>
</html>
"""

    with open(TABLE_HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html)

    safe_print(f"[SAVE] Table saved to {TABLE_HTML_FILE}", "green")


def save_alerts_to_json(alerts: list[dict], filename: str = ALERTS_OUTPUT_FILE):
    if not alerts:
        safe_print("Info: No alerts to export.", "dim")
        return

    export_data = []
    for a in alerts:
        export_data.append({
            "alert_id": a["alert_id"],
            "rule": a["rule"],
            "severity": a["severity"],
            "technique": a["technique"],
            "indicator": a["indicator"],
            "count": a["count"],
            "timestamp": a["timestamp"],
            "first_seen": a.get("first_seen", a["timestamp"]),
            "last_seen": a.get("last_seen", a["timestamp"]),
            "is_new": a.get("is_new", False)
        })

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=4, ensure_ascii=False)
    safe_print(f"[EXPORT] All alerts saved to {filename}", "green")


def update_alert_history(alerts: list[dict], history: dict):
    existing_alerts = {a["alert_id"]: a for a in history.get("alerts", [])}

    for alert in alerts:
        alert_id = alert["alert_id"]
        if alert_id in existing_alerts:
            existing_alerts[alert_id]["last_seen"] = alert["timestamp"]
            existing_alerts[alert_id]["count"] = alert["count"]
            existing_alerts[alert_id]["occurrences"] = existing_alerts[alert_id].get("occurrences", 1) + 1
        else:
            alert["occurrences"] = 1
            alert["is_new"] = True
            existing_alerts[alert_id] = alert

    history["alerts"] = list(existing_alerts.values())
    history["total_alerts_ever"] = len(history["alerts"])
    history["total_runs"] = history.get("total_runs", 0) + 1

    save_history(history)


def main():
    parser = argparse.ArgumentParser(
        description="Auth Log Anomaly Detector v2.1 | With Auto-Save Reports",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--log", required=True, help="Path to authentication log file")
    parser.add_argument("--rules", default="rules.yaml", help="Path to detection rules (YAML)")
    parser.add_argument("--format", choices=["json", "table", "rich"], default="rich", help="Output format")
    parser.add_argument("--notify", action="store_true", help="Trigger desktop notifications")
    parser.add_argument("--notify-all", action="store_true", help="Notify for ALL alerts (including existing)")
    parser.add_argument("--clear-history", action="store_true", help="Clear alert history before running")
    parser.add_argument("--no-save", action="store_true", help="Disable auto-save reports")
    args = parser.parse_args()

    history = load_history()

    if args.clear_history:
        history = {"alerts": [], "last_run": None}
        safe_print("[INFO] Alert history cleared.", "yellow")

    rules = load_rules(args.rules)
    logs = parse_logs(args.log)
    alerts = detect(logs, rules)

    new_alerts_count = 0
    for alert in alerts:
        alert["is_new"] = is_new_alert(alert, history)
        if alert["is_new"]:
            new_alerts_count += 1

    # Вывод таблицы
    if args.format == "json":
        print(json.dumps(alerts, indent=2, ensure_ascii=False))
    elif args.format == "rich" and RICH_AVAILABLE:
        print_table(alerts, new_alerts_count)
    else:
        print(f"{'Rule':<20} | {'Severity':<10} | {'IP':<16} | {'Count':<6} | {'Status':<12} | {'Technique'}")
        print("-" * 100)
        for a in alerts:
            status = "[NEW]" if a.get("is_new", False) else "[EXISTING]"
            print(
                f"{a['rule']:<20} | {a['severity']:<10} | {a['indicator']:<16} | {a['count']:<6} | {status:<12} | {a['technique']}")

    if alerts:
        safe_print(
            f"\n[INFO] Detected {len(alerts)} alert(s) ({new_alerts_count} new, {len(alerts) - new_alerts_count} existing)",
            "bold")
    else:
        safe_print("\n[INFO] No alerts detected.", "green")

    # Уведомления
    if args.notify and alerts:
        safe_print("\n[NOTIFY] Sending desktop notifications...", "dim")
        for alert in alerts:
            if alert.get("is_new", False) or args.notify_all:
                send_desktop_alert(alert, is_new=alert.get("is_new", False))
                log_notification(alert, alert.get("is_new", False))

    # Сохранение отчётов (если не отключено)
    if not args.no_save and alerts:
        safe_print("\n[SAVE] Auto-saving reports...", "dim")
        save_table_to_txt(alerts, new_alerts_count)
        save_table_to_csv(alerts)
        save_table_to_html(alerts, new_alerts_count)
        save_alerts_to_json(alerts)
        update_alert_history(alerts, history)

    safe_print(
        f"\n[STATS] History: {history.get('total_alerts_ever', 0)} unique alerts tracked over {history.get('total_runs', 0)} runs",
        "dim")
    safe_print(f"[INFO] Reports directory: {os.path.abspath(REPORTS_DIR)}", "dim")


if __name__ == "__main__":
    main()