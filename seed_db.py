from database import SecurityAlert, SessionLocal, engine
from datetime import datetime, timezone, timedelta
import hashlib


def create_sample_alerts():
    db = SessionLocal()

    sample_alerts = [
        {
            "rule": "ssh_bruteforce",
            "severity": "HIGH",
            "indicator": "192.168.1.100",
            "count": 15,
            "technique": "T1110.001"
        },
        {
            "rule": "sensitive_file_access",
            "severity": "CRITICAL",
            "indicator": "/etc/shadow",
            "count": 3,
            "technique": "T1003.008"
        },
        {
            "rule": "cron_modification",
            "severity": "HIGH",
            "indicator": "system_event",
            "count": 1,
            "technique": "T1053.003"
        },
        {
            "rule": "sudo_abuse",
            "severity": "MEDIUM",
            "indicator": "user_admin",
            "count": 8,
            "technique": "T1548.003"
        }
    ]

    for alert_data in sample_alerts:
        alert_id = hashlib.md5(
            f"{alert_data['rule']}:{alert_data['indicator']}:{alert_data['technique']}".encode()
        ).hexdigest()[:8] # nosec B324

        existing = db.query(SecurityAlert).filter(SecurityAlert.alert_id == alert_id).first()
        if not existing:
            alert = SecurityAlert(
                alert_id=alert_id,
                rule_name=alert_data["rule"],
                severity=alert_data["severity"],
                indicator=alert_data["indicator"],
                count=alert_data["count"],
                technique=alert_data["technique"],
                is_new=True,
                last_seen=datetime.now(timezone.utc) - timedelta(minutes=5)
            )
            db.add(alert)

    db.commit()
    print(" Database seeded with sample alerts!")
    db.close()

if __name__ == "__main__":
    create_sample_alerts()