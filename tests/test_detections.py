import json
from pathlib import Path

import pytest

from detections import ALL_DETECTIONS
from detections.admin_escalation import detect_admin_escalation
from detections.brute_force import detect_brute_force
from detections.impossible_travel import detect_impossible_travel
from detections.mfa_fatigue import detect_mfa_fatigue
from detections.suspicious_mfa import detect_suspicious_mfa

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "sample_events.json"


def _load_sample_events():
    with open(SAMPLE, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return [e for e in raw if "eventType" in e]


def _subset(uuids):
    want = set(uuids)
    return [e for e in _load_sample_events() if e.get("uuid") in want]


MFA_FATIGUE_UUIDS = [f"evt-mfa-{i:03d}" for i in range(1, 7)]
TRAVEL_UUIDS = ["evt-travel-001", "evt-travel-002"]
BRUTE_UUIDS = [f"evt-brute-{i:03d}" for i in range(1, 12)]
SUSPICIOUS_MFA_UUIDS = ["evt-mfaenroll-001", "evt-mfaenroll-002"]
ADMIN_UUIDS = ["evt-priv-001"]
BENIGN_UUIDS = ["evt-benign-001", "evt-benign-002"]


@pytest.mark.parametrize(
    "detect_fn,rule_name,uuids",
    [
        (detect_mfa_fatigue, "MFA Fatigue Attack", MFA_FATIGUE_UUIDS),
        (detect_impossible_travel, "Impossible Travel", TRAVEL_UUIDS),
        (detect_brute_force, "Brute Force Attack", BRUTE_UUIDS),
        (detect_suspicious_mfa, "Suspicious MFA Enrollment", SUSPICIOUS_MFA_UUIDS),
        (
            detect_admin_escalation,
            "Admin Privilege Escalation (After Hours)",
            ADMIN_UUIDS,
        ),
    ],
)
def test_rule_alerts_on_scenario_slice(detect_fn, rule_name, uuids):
    events = _subset(uuids)
    alerts = detect_fn(events)
    matching = [a for a in alerts if a.get("rule_name") == rule_name]
    assert len(matching) >= 1


def test_benign_events_trigger_no_alerts():
    events = _subset(BENIGN_UUIDS)
    for detect_fn in ALL_DETECTIONS:
        assert detect_fn(events) == [], detect_fn.__name__


def test_full_sample_one_alert_per_rule():
    events = _load_sample_events()
    expected = [
        (detect_mfa_fatigue, 1),
        (detect_impossible_travel, 1),
        (detect_brute_force, 1),
        (detect_suspicious_mfa, 1),
        (detect_admin_escalation, 1),
    ]
    for fn, n in expected:
        assert len(fn(events)) == n, fn.__name__
