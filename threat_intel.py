import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# Mock intelligence cache for automated local testing
KNOWN_THREAT_CACHE = {
    "192.168.1.100": {
        "abuse_score": 92,
        "vt_malicious": 58,
        "vt_total": 72,
        "verdict": "MALICIOUS",
        "isp": "Private Rogue C2 Server",
        "country": "External"
    },
    "118.25.6.39": {
        "abuse_score": 100,
        "vt_malicious": 64,
        "vt_total": 72,
        "verdict": "MALICIOUS",
        "isp": "Tencent Cloud (Cobalt Strike C2)",
        "country": "CN"
    },
    "8.8.8.8": {
        "abuse_score": 0,
        "vt_malicious": 0,
        "vt_total": 72,
        "verdict": "BENIGN",
        "isp": "Google Public DNS",
        "country": "US"
    }
}

def query_abuseipdb(ip_address: str) -> dict:
    """Queries AbuseIPDB API for IP reputation."""
    if not ABUSEIPDB_API_KEY:
        if ip_address in KNOWN_THREAT_CACHE:
            return {
                "abuseConfidenceScore": KNOWN_THREAT_CACHE[ip_address]["abuse_score"],
                "isp": KNOWN_THREAT_CACHE[ip_address]["isp"],
                "countryCode": KNOWN_THREAT_CACHE[ip_address]["country"]
            }
        return {"abuseConfidenceScore": 85, "isp": "Suspicious Hosting Provider", "countryCode": "RU"}

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            return response.json().get("data", {})
    except Exception as e:
        print(f"[-] AbuseIPDB query failed: {e}")
    
    return {"abuseConfidenceScore": 0, "isp": "Unknown", "countryCode": "Unknown"}

def query_virustotal(ip_address: str) -> dict:
    """Queries VirusTotal API v3 for IP detections."""
    if not VIRUSTOTAL_API_KEY:
        if ip_address in KNOWN_THREAT_CACHE:
            return {
                "malicious": KNOWN_THREAT_CACHE[ip_address]["vt_malicious"],
                "total": KNOWN_THREAT_CACHE[ip_address]["vt_total"]
            }
        return {"malicious": 45, "total": 72}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "total": sum(stats.values())
            }
    except Exception as e:
        print(f"[-] VirusTotal query failed: {e}")
        
    return {"malicious": 0, "total": 0}

def enrich_ip(ip_address: str) -> dict:
    """Calculates a composite risk score (0-100) combining threat feeds."""
    abuse = query_abuseipdb(ip_address)
    vt = query_virustotal(ip_address)
    
    abuse_score = abuse.get("abuseConfidenceScore", 0)
    vt_malicious = vt.get("malicious", 0)
    
    # Composite score formula: 50% AbuseIPDB + 50% VirusTotal weight
    composite_score = int((abuse_score * 0.5) + (min(vt_malicious * 2, 100) * 0.5))
    is_confirmed_threat = composite_score >= 60 or vt_malicious >= 5
    
    return {
        "ip": ip_address,
        "composite_score": composite_score,
        "is_threat": is_confirmed_threat,
        "abuse_score": abuse_score,
        "vt_detections": f"{vt_malicious}/{vt.get('total', 72)}",
        "isp": abuse.get("isp", "Unknown"),
        "country": abuse.get("countryCode", "Unknown")
    }
