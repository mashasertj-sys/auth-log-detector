from main import load_rules, detect
import tempfile, os

RULES = [
    {"name": "test_rule", "pattern": r"Failed .* from ([0-9.]+)", "threshold": 2, "severity": "HIGH", "technique": "T0000"}
]

def test_detect_triggers():
    logs = ["Failed password from 1.1.1.1", "Failed password from 1.1.1.1", "Failed password from 2.2.2.2"]
    alerts = detect(logs, RULES)
    assert len(alerts) == 1
    assert alerts[0]["indicator"] == "1.1.1.1"
    assert alerts[0]["count"] == 2

def test_detect_no_trigger():
    logs = ["Failed password from 1.1.1.1"]
    alerts = detect(logs, RULES)
    assert len(alerts) == 0