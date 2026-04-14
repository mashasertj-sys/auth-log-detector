import time
import os
import re
import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from database import get_db, SecurityAlert

LOG_FILE = "activity.log"
CHECK_INTERVAL = 3
WINDOW_RESET = 60

RULES = [
    {"name": "ssh_bruteforce", "pattern": r"Failed password for .* from ([0-9.]+)", "threshold": 3, "severity": "HIGH", "technique": "T1110.001"},
    {"name": "sensitive_file_access", "pattern": r"cat /etc/(shadow|passwd)", "threshold": 1, "severity": "CRITICAL", "technique": "T1003.008"},
    {"name": "cron_modification", "pattern": r"cron.*EDIT", "threshold": 1, "severity": "HIGH", "technique": "T1053.003"},
    {"name": "sudo_abuse", "pattern": r"sudo:.*COMMAND=(.+)", "threshold": 3, "severity": "MEDIUM", "technique": "T1548.003"}
]

class LogMonitor:
    def __init__(self):
        self.counters = defaultdict(lambda: defaultdict(int))
        self.last_position = 0

    def tail_new_lines(self):
        if not os.path.exists(LOG_FILE):
            return []
        with open(LOG_FILE, 'r') as f:
            f.seek(self.last_position)
            new_lines = f.readlines()
            self.last_position = f.tell()
        return [line.strip() for line in new_lines if line.strip()]

    def process_lines(self, lines):
        for line in lines:
            for rule in RULES:
                match = re.search(rule["pattern"], line)
                if match:
                    indicator = match.group(1) if match.lastindex else "system"
                    self.counters[rule["name"]][indicator] += 1

    def check_thresholds(self):
        triggered = []
        for rule_name, indicators in self.counters.items():
            rule = next(r for r in RULES if r["name"] == rule_name)
            for indicator, count in indicators.items():
                if count >= rule["threshold"]:
                    triggered.append({
                        "rule": rule_name,
                        "severity": rule["severity"],
                        "technique": rule["technique"],
                        "indicator": indicator,
                        "count": count
                    })
        return triggered

    def save_alerts(self, alerts):
        if not alerts: return
        db_gen = get_db()
        db = next(db_gen)
        try:
            for a in alerts:
                alert_id = hashlib.md5(f"{a['rule']}:{a['indicator']}:{a['technique']}".encode()).hexdigest()[:8]
                existing = db.query(SecurityAlert).filter(SecurityAlert.alert_id == alert_id).first()
                if existing:
                    existing.count = a['count']
                    existing.last_seen = datetime.now(timezone.utc)
                    existing.is_new = False
                else:
                    db.add(SecurityAlert(
                        alert_id=alert_id, rule_name=a['rule'], severity=a['severity'],
                        indicator=a['indicator'], count=a['count'], technique=a['technique'], is_new=True
                    ))
            db.commit()
            print(f" Saved {len(alerts)} alert(s) to DB")
        except Exception as e:
            db.rollback()
            print(f" DB Error: {e}")
        finally:
            db.close()

    def reset_counters(self):
        self.counters.clear()

    def run(self):
        print(" Log Monitor started. Watching for threats...")
        last_reset = time.time()
        while True:
            try:
                new_lines = self.tail_new_lines()
                if new_lines:
                    self.process_lines(new_lines)

                triggered = self.check_thresholds()
                if triggered:
                    self.save_alerts(triggered)
                    for t in triggered:
                        self.counters[t['rule']].pop(t['indicator'], None)

                if time.time() - last_reset > WINDOW_RESET:
                    self.reset_counters()
                    last_reset = time.time()

                time.sleep(CHECK_INTERVAL)
            except KeyboardInterrupt:
                print("\n Monitor stopped.")
                break
            except Exception as e:
                print(f" Error: {e}")
                time.sleep(2)

if __name__ == "__main__":
    LogMonitor().run()