# Okta Detection Engine

A Python-based detection engine that parses Okta System Log events and identifies 5 common identity-based attack patterns.

## What You'll Learn

| Detection Rule | Attack Technique | MITRE ATT&CK |
|---|---|---|
| MFA Fatigue | Push-spam to trick user into approving MFA | T1621 |
| Impossible Travel | Credential use from geographically impossible locations | T1078 |
| Brute Force | Automated password guessing from a single IP | T1110.001 |
| Suspicious MFA Enrollment | Attacker registers their own MFA after account takeover | T1098.005 |
| Admin Privilege Escalation | After-hours admin grants indicating insider threat | T1078.004 |

## Setup

```bash
pip install requests   # only external dependency
```

### Optional: VirusTotal API key (for IP enrichment)
```bash
export VT_API_KEY=your_virustotal_api_key_here
```

### Optional: Okta API token (for live event ingestion)
```bash
export OKTA_API_TOKEN=your_okta_api_token_here
```

## Usage

**Run against sample data (start here):**
```bash
python okta_detector.py --input sample_events.json
```

**Save alerts to file:**
```bash
python okta_detector.py --input sample_events.json --output alerts.json
```

**With IP enrichment (geolocation + VirusTotal):**
```bash
python okta_detector.py --input sample_events.json --enrich --output alerts.json
```

**Live from Okta API:**
```bash
python okta_detector.py --api --domain myorg.okta.com --since 2026-02-25T00:00:00Z
```

## Project Structure

```
okta-detection-engine/
  okta_detector.py        # Main CLI -- loads events, runs rules, outputs alerts
  enrichment.py           # IP enrichment via VirusTotal + ip-api.com
  sample_events.json      # Test data with scenarios for each rule
  detections/
    __init__.py           # Registers all detection functions
    mfa_fatigue.py        # 5+ push events + MFA success in 10 min
    impossible_travel.py  # 500+ mile gap in 60 min (Haversine formula)
    brute_force.py        # 10+ failed logins from same IP in 5 min
    suspicious_mfa.py     # MFA enrolled within 10 min of unusual login
    admin_escalation.py   # Privilege grant outside 7AM-7PM
```

## How Each Detection Works

### MFA Fatigue
Groups `system.push.send_factor_verify_push` events by user, checks for 5+ in a 10-minute sliding window, then looks for a `user.authentication.auth_via_mfa` success in the same window. Real-world: Uber (2022), Cisco (2022).

### Impossible Travel
Pairs consecutive `user.session.start` events per user, calculates great-circle distance using the Haversine formula, and flags pairs >500 miles apart within 60 minutes. Watch for VPN false positives.

### Brute Force
Groups failed `user.session.start` events by source IP, uses a sliding window to find 10+ failures within 5 minutes. Also tracks which user accounts were targeted.

### Suspicious MFA Enrollment
Correlates `user.mfa.factor.activate` with recent `user.session.start` from unusual locations (outside known countries). Flags enrollments within 10 minutes of the suspicious login.

### Admin Privilege Escalation
Flags `user.account.privilege.grant` events where the UTC hour is before 7 AM or after 7 PM. In production, convert to the org's local timezone.

## Alert Format

Each alert is a JSON object:
```json
{
  "rule_name": "Brute Force Attack",
  "severity": "HIGH",
  "user": "admin@acme.com",
  "source_ip": "192.0.2.200",
  "timestamp": "2026-02-26T08:00:00.000Z",
  "details": { ... },
  "recommended_action": "1. Block the source IP...",
  "enrichment_data": { ... }
}
```

## Extending the Lab

To add a new detection rule:
1. Create `detections/your_rule.py` with a `def detect_your_rule(events)` function
2. Return a list of alert dicts matching the format above
3. Import and add it to `ALL_DETECTIONS` in `detections/__init__.py`
