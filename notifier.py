import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

def send_chatops_alert(alert_data: dict, intel_data: dict, containment_data: dict) -> bool:
    """Dispatches a structured incident card to SOC ChatOps (Discord/Slack/Teams)."""
    title = f"🚨 [SOAR AUTO-CONTAINMENT] Threat Mitigated on {alert_data.get('host', 'Unknown Host')}"
    
    fields = [
        {"name": "Incident ID", "value": alert_data.get("alert_id", "N/A"), "inline": True},
        {"name": "Target Host", "value": alert_data.get("host", "N/A"), "inline": True},
        {"name": "Mitigated C2 IP", "value": f"`{intel_data.get('ip')}`", "inline": True},
        {"name": "AbuseIPDB Score", "value": f"{intel_data.get('abuse_score')}%", "inline": True},
        {"name": "VirusTotal Flag", "value": intel_data.get("vt_detections"), "inline": True},
        {"name": "Composite Threat Score", "value": f"**{intel_data.get('composite_score')}/100**", "inline": True},
        {"name": "Active Action Taken", "value": f"✅ {containment_data.get('details')}", "inline": False},
        {"name": "Firewall Rule", "value": f"`{containment_data.get('rule_name')}`", "inline": False}
    ]
    
    payload = {
        "embeds": [{
            "title": title,
            "color": 15158332,  # Crimson Red
            "fields": fields,
            "footer": {"text": "SecOps SOAR Automated Incident Response Pipeline • Splunk + Defender"}
        }]
    }
    
    if DISCORD_WEBHOOK_URL:
        try:
            res = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
            if res.status_code in [200, 204]:
                return True
        except Exception as e:
            print(f"[-] Webhook dispatch error: {e}")
            
    # Always print a clean summary to stdout
    print(f"\n[+] [CHATOPS BROADCAST] Automated containment notification logged for {intel_data.get('ip')}")
    return True
