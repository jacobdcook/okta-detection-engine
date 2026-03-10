"""
MFA Fatigue Detection
=====================
WHAT: Detects MFA push-spam attacks where an attacker who already has the
      victim's password sends repeated push notifications hoping the user
      will accidentally (or out of frustration) approve one.

RULE: 5+ system.push.send_factor_verify_push events from the same user
      within a 10-minute window, followed by a user.authentication.auth_via_mfa
      event (meaning the victim approved the push).

WHY IT MATTERS: This is a real-world attack used against Cisco, Uber, and
      many others. Okta even added "number matching" MFA to counter it.
"""

from datetime import datetime, timedelta, timezone

PUSH_EVENT = "system.push.send_factor_verify_push"
MFA_SUCCESS = "user.authentication.auth_via_mfa"
WINDOW = timedelta(minutes=10)
THRESHOLD = 5


def detect_mfa_fatigue(events):
    alerts = []

    pushes_by_user = {}
    mfa_by_user = {}

    for evt in events:
        etype = evt.get("eventType", "")
        uid = evt.get("actor", {}).get("id", "")
        if not uid:
            continue
        if etype == PUSH_EVENT:
            pushes_by_user.setdefault(uid, []).append(evt)
        elif etype == MFA_SUCCESS:
            mfa_by_user.setdefault(uid, []).append(evt)

    for uid, pushes in pushes_by_user.items():
        pushes.sort(key=lambda e: e["published"])

        for i in range(len(pushes) - THRESHOLD + 1):
            window_start = _parse(pushes[i]["published"])
            window_end = _parse(pushes[i + THRESHOLD - 1]["published"])

            if window_end - window_start > WINDOW:
                continue

            for mfa_evt in mfa_by_user.get(uid, []):
                mfa_time = _parse(mfa_evt["published"])
                if window_start <= mfa_time <= window_end + WINDOW:
                    alerts.append({
                        "rule_name": "MFA Fatigue Attack",
                        "severity": "CRITICAL",
                        "user": pushes[0]["actor"].get("alternateId", uid),
                        "source_ip": pushes[0].get("client", {}).get("ipAddress", "unknown"),
                        "timestamp": mfa_evt["published"],
                        "details": {
                            "push_count": len(pushes),
                            "window_start": pushes[i]["published"],
                            "window_end": pushes[i + THRESHOLD - 1]["published"],
                            "mfa_approved_at": mfa_evt["published"],
                        },
                        "recommended_action": (
                            "1. Revoke user sessions immediately\n"
                            "2. Reset MFA factors\n"
                            "3. Contact user to confirm they approved the push\n"
                            "4. Enable MFA number matching if not already active"
                        ),
                    })
                    break
            break

    return alerts


def _parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
