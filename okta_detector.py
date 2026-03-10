#!/usr/bin/env python3
"""
Okta Detection Engine
=====================
A lightweight Python-based detection engine that parses Okta System Log
events and fires alerts for 5 common attack patterns.

USAGE:
  python okta_detector.py --input sample_events.json --output alerts.json
  python okta_detector.py --input sample_events.json --enrich
  python okta_detector.py --input sample_events.json --enrich --output alerts.json

ARCHITECTURE:
  1. Load events from JSON file (or Okta API -- see --api flag)
  2. Pass events through each detection module
  3. Optionally enrich flagged IPs with VirusTotal + geolocation
  4. Output structured JSON alerts

Each detection module follows the same interface:
  def detect_<name>(events: list[dict]) -> list[dict]
  Input:  list of raw Okta System Log event dicts
  Output: list of alert dicts with rule_name, severity, user, etc.
"""

import argparse
import json
import sys
import os
import requests

from detections import ALL_DETECTIONS
from enrichment import enrich_alerts


def load_events_from_file(path):
    """Load Okta events from a JSON file."""
    with open(path, "r") as f:
        events = json.load(f)
    return [e for e in events if "eventType" in e]


def load_events_from_api(domain, api_token, since=None):
    """
    Fetch events from the Okta System Log API.

    HOW OKTA'S API WORKS:
      - Endpoint: https://{domain}/api/v1/logs
      - Auth: SSWS token in the Authorization header
      - Pagination: follow the 'next' link in the response headers
      - Rate limit: 120 requests per minute (check X-Rate-Limit-Remaining)

    To get an API token:
      1. Log into Okta admin console
      2. Security -> API -> Tokens -> Create Token
      3. Set as env var: export OKTA_API_TOKEN=your_token
    """
    url = f"https://{domain}/api/v1/logs"
    headers = {"Authorization": f"SSWS {api_token}"}
    params = {"limit": 1000}
    if since:
        params["since"] = since

    all_events = []
    while url:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        all_events.extend(resp.json())

        url = None
        params = None
        links = resp.headers.get("Link", "")
        for link in links.split(","):
            if 'rel="next"' in link:
                url = link.split(";")[0].strip(" <>")
                break

    return all_events


def run_detections(events):
    """Run all detection rules against the event set."""
    all_alerts = []
    for detect_fn in ALL_DETECTIONS:
        alerts = detect_fn(events)
        all_alerts.extend(alerts)
    return all_alerts


def main():
    parser = argparse.ArgumentParser(
        description="Okta Detection Engine -- detect attacks in Okta System Log events",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python okta_detector.py --input sample_events.json\n"
            "  python okta_detector.py --input sample_events.json --output alerts.json\n"
            "  python okta_detector.py --input sample_events.json --enrich\n"
            "  python okta_detector.py --api --domain myorg.okta.com --since 2026-02-25T00:00:00Z\n"
        ),
    )

    parser.add_argument("--input", "-i", help="Path to JSON file with Okta events")
    parser.add_argument("--api", action="store_true", help="Fetch events from Okta API instead of file")
    parser.add_argument("--domain", help="Okta domain (e.g., myorg.okta.com)")
    parser.add_argument("--since", help="Fetch events since this ISO timestamp (API mode)")
    parser.add_argument("--output", "-o", help="Path to write alerts JSON (default: stdout)")
    parser.add_argument("--enrich", action="store_true", help="Enrich IPs with VirusTotal + geolocation")

    args = parser.parse_args()

    if args.api:
        if not args.domain:
            parser.error("--domain is required when using --api")
        api_token = os.environ.get("OKTA_API_TOKEN", "")
        if not api_token:
            print("ERROR: Set OKTA_API_TOKEN environment variable", file=sys.stderr)
            sys.exit(1)
        events = load_events_from_api(args.domain, api_token, args.since)
    elif args.input:
        events = load_events_from_file(args.input)
    else:
        parser.error("Provide --input <file> or --api")

    print(f"[*] Loaded {len(events)} events", file=sys.stderr)

    alerts = run_detections(events)
    print(f"[*] Generated {len(alerts)} alerts", file=sys.stderr)

    if args.enrich and alerts:
        print("[*] Enriching IPs...", file=sys.stderr)
        alerts = enrich_alerts(alerts)

    output_json = json.dumps(alerts, indent=2, default=str)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output_json)
        print(f"[*] Alerts written to {args.output}", file=sys.stderr)
    else:
        print(output_json)


if __name__ == "__main__":
    main()
