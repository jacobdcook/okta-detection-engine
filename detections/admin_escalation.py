"""
Admin Privilege Escalation Detection
======================================
WHAT: Detects admin privilege grants that occur outside normal business
      hours, which may indicate an insider threat or compromised admin.

RULE: A user.account.privilege.grant event occurs before 7:00 AM or
      after 7:00 PM (based on the event timestamp).

WHY IT MATTERS: Legitimate privilege changes go through change management
      during business hours. After-hours admin grants are a common indicator
      of compromised admin accounts or insider threats.

LIMITATIONS: Uses UTC time. In production, convert to org's local timezone.
"""

from datetime import datetime, timezone

PRIV_GRANT = "user.account.privilege.grant"
BUSINESS_HOURS_START = 7
BUSINESS_HOURS_END = 19


def detect_admin_escalation(events):
    alerts = []

    for evt in events:
        if evt.get("eventType") != PRIV_GRANT:
            continue

        ts = _parse(evt["published"])
        hour = ts.hour

        if BUSINESS_HOURS_START <= hour < BUSINESS_HOURS_END:
            continue

        actor = evt.get("actor", {})
        targets = evt.get("target", [])
        target_user = targets[0] if targets else {}

        alerts.append({
            "rule_name": "Admin Privilege Escalation (After Hours)",
            "severity": "HIGH",
            "user": actor.get("alternateId", "unknown"),
            "source_ip": evt.get("client", {}).get("ipAddress", "unknown"),
            "timestamp": evt["published"],
            "details": {
                "actor": actor.get("alternateId", "unknown"),
                "target_user": target_user.get("alternateId", "unknown"),
                "event_hour_utc": hour,
                "business_hours": f"{BUSINESS_HOURS_START}:00-{BUSINESS_HOURS_END}:00 UTC",
                "location": evt.get("client", {}).get("geographicalContext", {}).get("city", "Unknown"),
            },
            "recommended_action": (
                "1. Verify with the actor that this was an authorized change\n"
                "2. Check if a change request/ticket exists for this grant\n"
                "3. Review the target user's subsequent activity\n"
                "4. If unauthorized, revoke the privilege and lock both accounts"
            ),
        })

    return alerts


def _parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
