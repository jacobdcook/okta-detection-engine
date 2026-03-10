"""
Brute Force Detection
=====================
WHAT: Detects password-guessing attacks where an attacker tries many
      credentials from the same source IP.

RULE: 10+ failed user.session.start events from the same IP address
      within a 5-minute window.

WHY THIS WORKS: Legitimate users mistype passwords occasionally, but
      10+ failures in 5 minutes from one IP is almost always automated.

VARIATIONS IN THE WILD:
  - Password spraying: few attempts per user, many users (evades per-user limits)
  - Credential stuffing: using leaked username/password pairs from breaches
  - Distributed brute force: same attack spread across many IPs (harder to detect)
"""

from datetime import datetime, timedelta, timezone
from collections import defaultdict

SESSION_START = "user.session.start"
WINDOW = timedelta(minutes=5)
THRESHOLD = 10


def detect_brute_force(events):
    alerts = []

    failures_by_ip = defaultdict(list)
    for evt in events:
        if evt.get("eventType") != SESSION_START:
            continue
        if evt.get("outcome", {}).get("result") != "FAILURE":
            continue
        ip = evt.get("client", {}).get("ipAddress", "")
        if ip:
            failures_by_ip[ip].append(evt)

    for ip, failures in failures_by_ip.items():
        failures.sort(key=lambda e: e["published"])

        for i in range(len(failures)):
            window_start = _parse(failures[i]["published"])
            count = 0
            targeted_users = set()

            for j in range(i, len(failures)):
                evt_time = _parse(failures[j]["published"])
                if evt_time - window_start > WINDOW:
                    break
                count += 1
                targeted_users.add(failures[j]["actor"].get("alternateId", "unknown"))

            if count >= THRESHOLD:
                geo = failures[i].get("client", {}).get("geographicalContext", {})
                alerts.append({
                    "rule_name": "Brute Force Attack",
                    "severity": "HIGH",
                    "user": ", ".join(targeted_users),
                    "source_ip": ip,
                    "timestamp": failures[i]["published"],
                    "details": {
                        "failed_attempts": count,
                        "window_minutes": 5,
                        "targeted_users": list(targeted_users),
                        "source_country": geo.get("country", "Unknown"),
                        "source_city": geo.get("city", "Unknown"),
                    },
                    "recommended_action": (
                        "1. Block the source IP at firewall/WAF level\n"
                        "2. Check if any targeted accounts were eventually compromised\n"
                        "3. Force password reset for targeted accounts\n"
                        "4. Review if IP appears in threat intelligence feeds"
                    ),
                })
                break

    return alerts


def _parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
