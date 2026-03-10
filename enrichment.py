"""
IP Enrichment Module
====================
Enriches IP addresses with threat intelligence and geolocation data.

TWO DATA SOURCES:
  1. ip-api.com   -- Free geolocation (no API key needed, 45 req/min limit)
  2. VirusTotal   -- Threat reputation (free API key, 4 req/min on free tier)

HOW TO GET A VIRUSTOTAL API KEY:
  1. Go to https://www.virustotal.com/
  2. Create a free account
  3. Go to your profile -> API Key
  4. Set it as an environment variable: export VT_API_KEY=your_key_here

RATE LIMITING: Both APIs have rate limits. This module caches results
  to avoid hitting the same IP twice. In production, you'd use Redis
  or a database for persistent caching.
"""

import os
import requests

VT_API_KEY = os.environ.get("VT_API_KEY", "")
GEO_CACHE = {}
VT_CACHE = {}

PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "127.")


def enrich_ip(ip):
    """Enrich a single IP with geolocation and threat data."""
    if not ip or ip == "unknown" or any(ip.startswith(p) for p in PRIVATE_PREFIXES):
        return {"ip": ip, "note": "Private/internal IP -- skipped enrichment"}

    result = {"ip": ip}
    result["geolocation"] = _get_geolocation(ip)
    result["virustotal"] = _get_virustotal(ip)
    return result


def enrich_alerts(alerts):
    """Add enrichment_data to each alert based on its source_ip."""
    for alert in alerts:
        ip = alert.get("source_ip", "")
        alert["enrichment_data"] = enrich_ip(ip)
    return alerts


def _get_geolocation(ip):
    """Query ip-api.com for geolocation data (free, no key needed)."""
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]

    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            result = {
                "country": data.get("country"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
            }
            GEO_CACHE[ip] = result
            return result
    except requests.RequestException as e:
        return {"error": f"Geolocation lookup failed: {e}"}

    return {"error": f"HTTP {resp.status_code}"}


def _get_virustotal(ip):
    """Query VirusTotal for IP reputation (requires VT_API_KEY env var)."""
    if not VT_API_KEY:
        return {"note": "VT_API_KEY not set -- skipping VirusTotal lookup"}

    if ip in VT_CACHE:
        return VT_CACHE[ip]

    try:
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            result = {
                "malicious_votes": stats.get("malicious", 0),
                "suspicious_votes": stats.get("suspicious", 0),
                "harmless_votes": stats.get("harmless", 0),
                "reputation_score": data.get("reputation", 0),
                "as_owner": data.get("as_owner", ""),
                "country": data.get("country", ""),
            }
            VT_CACHE[ip] = result
            return result
        elif resp.status_code == 429:
            return {"error": "Rate limited -- VirusTotal free tier allows 4 req/min"}
    except requests.RequestException as e:
        return {"error": f"VirusTotal lookup failed: {e}"}

    return {"error": f"HTTP {resp.status_code}"}
