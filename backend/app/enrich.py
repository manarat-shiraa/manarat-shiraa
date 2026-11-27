"""إثراء التنبيه بمعلومات سمعة عناوين الـ IP.

أولاً من القائمة المحلية (data/threat_intel.json) عشان الديمو يشتغل بدون نت،
وبعدها من AbuseIPDB لو فيه مفتاح API في .env.
"""
from __future__ import annotations

import ipaddress
import json
from functools import lru_cache

import httpx

from . import config


@lru_cache(maxsize=1)
def _local_intel() -> dict:
    return json.loads(config.THREAT_INTEL_FILE.read_text(encoding="utf-8")).get("malicious_ips", {})


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


@lru_cache(maxsize=256)
def _abuseipdb(ip: str) -> dict | None:
    if not config.ABUSEIPDB_API_KEY:
        return None
    try:
        r = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=8,
        )
        r.raise_for_status()
        d = r.json()["data"]
        return {"score": d.get("abuseConfidenceScore", 0), "country": d.get("countryCode", "")}
    except Exception:
        return None


def enrich_ips(*ips: str) -> list[dict]:
    findings = []
    for ip in {i for i in ips if i}:
        local = _local_intel().get(ip)
        if local:
            findings.append({"ip": ip, "malicious": True, "source": "local", "note": local})
            continue
        if not _is_public(ip):
            continue
        remote = _abuseipdb(ip)
        if remote is not None:
            findings.append(
                {
                    "ip": ip,
                    "malicious": remote["score"] >= 50,
                    "source": "abuseipdb",
                    "note": f"درجة السمعة السيئة {remote['score']}٪ ({remote['country']})",
                }
            )
    return findings
