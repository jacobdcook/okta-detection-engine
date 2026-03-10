"""
Suspicious MFA Enrollment Detection
=====================================
WHAT: Detects when an attacker enrolls their own MFA device immediately
      after compromising an account, ensuring persistent access.

RULE: A user.mfa.factor.activate event occurs within 10 minutes of a
      login (user.session.start) from a new or unusual IP/location.

WHY IT MATTERS: This is a common post-compromise persistence technique.
      Once an attacker registers their own authenticator app or hardware
      key, they can bypass MFA even after the victim resets their password.

REAL-WORLD: In the 2022 Uber breach, the attacker enrolled a new MFA
      device after gaining initial access, maintaining persistence.
"""

from datetime import datetime, timedelta, timezone

SESSION_START = "user.session.start"
MFA_ACTIVATE = "user.mfa.factor.activate"
WINDOW = timedelta(minutes=10)

KNOWN_COUNTRIES = {"United States"}


def detect_suspicious_mfa(events):
    alerts = []

    logins_by_user = {}
    mfa_activations = []

    for evt in events:
        etype = evt.get("eventType", "")
        uid = evt.get("actor", {}).get("id", "")
        if etype == SESSION_START and evt.get("outcome", {}).get("result") == "SUCCESS":
            logins_by_user.setdefault(uid, []).append(evt)
        elif etype == MFA_ACTIVATE:
            mfa_activations.append(evt)

    for mfa_evt in mfa_activations:
        uid = mfa_evt.get("actor", {}).get("id", "")
        mfa_time = _parse(mfa_evt["published"])
        mfa_ip = mfa_evt.get("client", {}).get("ipAddress", "")

        for login in logins_by_user.get(uid, []):
            login_time = _parse(login["published"])
            login_country = (
                login.get("client", {})
                .get("geographicalContext", {})
                .get("country", "Unknown")
            )

            time_diff = mfa_time - login_time
            if not (timedelta(0) <= time_diff <= WINDOW):
                continue

            if login_country not in KNOWN_COUNTRIES:
                factor_name = "Unknown"
                for t in mfa_evt.get("target", []):
                    if t.get("type") == "Factor":
                        factor_name = t.get("displayName", "Unknown")

                alerts.append({
                    "rule_name": "Suspicious MFA Enrollment",
                    "severity": "CRITICAL",
                    "user": mfa_evt["actor"].get("alternateId", uid),
                    "source_ip": mfa_ip,
                    "timestamp": mfa_evt["published"],
                    "details": {
                        "login_time": login["published"],
                        "mfa_enrolled_at": mfa_evt["published"],
                        "minutes_after_login": round(time_diff.total_seconds() / 60, 1),
                        "login_country": login_country,
                        "factor_enrolled": factor_name,
                    },
                    "recommended_action": (
                        "1. Immediately deactivate the newly enrolled MFA factor\n"
                        "2. Revoke all active sessions for this user\n"
                        "3. Reset password and all MFA factors\n"
                        "4. Investigate the login source IP for other compromised accounts"
                    ),
                })
                break

    return alerts


def _parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
