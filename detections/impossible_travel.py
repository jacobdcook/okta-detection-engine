"""
Impossible Travel Detection
============================
WHAT: Detects when the same user logs in from two locations that are
      physically impossible to travel between in the elapsed time.

RULE: Two user.session.start events from the same user where the
      geolocations are 500+ miles apart within 60 minutes.

HOW THE MATH WORKS: We use the Haversine formula to calculate the
      great-circle distance between two lat/lon coordinates on Earth.

WHY IT MATTERS: If Bob logs in from NYC at 10:00 and from Tokyo at
      10:30, he didn't fly 6,700 miles in 30 minutes. Someone else
      has his credentials.

FALSE POSITIVES: VPN usage, corporate proxies, and mobile handoffs
      can cause benign impossible travel. In production, you'd maintain
      a whitelist of known VPN exit IPs.
"""

import math
from datetime import datetime, timedelta, timezone

SESSION_START = "user.session.start"
DISTANCE_THRESHOLD_MILES = 500
TIME_WINDOW = timedelta(minutes=60)


def detect_impossible_travel(events):
    alerts = []

    sessions_by_user = {}
    for evt in events:
        if evt.get("eventType") != SESSION_START:
            continue
        if evt.get("outcome", {}).get("result") != "SUCCESS":
            continue
        uid = evt.get("actor", {}).get("id", "")
        if uid:
            sessions_by_user.setdefault(uid, []).append(evt)

    for uid, sessions in sessions_by_user.items():
        sessions.sort(key=lambda e: e["published"])

        for i in range(len(sessions) - 1):
            evt_a, evt_b = sessions[i], sessions[i + 1]
            time_a = _parse(evt_a["published"])
            time_b = _parse(evt_b["published"])
            elapsed = time_b - time_a

            if elapsed > TIME_WINDOW:
                continue

            geo_a = evt_a.get("client", {}).get("geographicalContext", {}).get("geolocation", {})
            geo_b = evt_b.get("client", {}).get("geographicalContext", {}).get("geolocation", {})

            if not (geo_a.get("lat") and geo_b.get("lat")):
                continue

            distance = _haversine(
                geo_a["lat"], geo_a["lon"],
                geo_b["lat"], geo_b["lon"],
            )

            if distance >= DISTANCE_THRESHOLD_MILES:
                city_a = evt_a["client"]["geographicalContext"].get("city", "Unknown")
                city_b = evt_b["client"]["geographicalContext"].get("city", "Unknown")
                alerts.append({
                    "rule_name": "Impossible Travel",
                    "severity": "HIGH",
                    "user": evt_a["actor"].get("alternateId", uid),
                    "source_ip": evt_b.get("client", {}).get("ipAddress", "unknown"),
                    "timestamp": evt_b["published"],
                    "details": {
                        "location_a": city_a,
                        "location_b": city_b,
                        "distance_miles": round(distance, 1),
                        "elapsed_minutes": round(elapsed.total_seconds() / 60, 1),
                        "ip_a": evt_a.get("client", {}).get("ipAddress"),
                        "ip_b": evt_b.get("client", {}).get("ipAddress"),
                    },
                    "recommended_action": (
                        "1. Verify with user which login was legitimate\n"
                        "2. Terminate the suspicious session\n"
                        "3. Force password reset\n"
                        "4. Check if either IP is a known VPN (reduces false positives)"
                    ),
                })

    return alerts


def _haversine(lat1, lon1, lat2, lon2):
    """Calculate distance in miles between two lat/lon points using Haversine formula."""
    R = 3958.8
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return R * 2 * math.asin(math.sqrt(a))


def _parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
