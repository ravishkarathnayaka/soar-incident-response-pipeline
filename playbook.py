import datetime
import json
import os
from threat_intel import enrich_ip
from containment import block_ip_firewall
from notifier import send_chatops_alert

def run_containment_playbook(alert: dict) -> dict:
    """Core SOAR Playbook: Enriches, evaluates, and mitigates high-confidence threats."""
    alert_id = alert.get("alert_id", "SEC-ALERT-UNKNOWN")
    c2_ip = alert.get("c2_ip") or alert.get("remote_ip")
    
    print(f"\n[*] Executing SOAR Playbook for Alert: {alert_id}")
    print(f"    - Target Endpoint : {alert.get('host')}")
    print(f"    - Extracted C2 IP : {c2_ip}")
    print(f"    - Adversary Vector: {alert.get('technique', 'Unknown')}")
    
    # Step 1: Threat Intelligence Enrichment
    print("    [1/3] Querying Threat Intelligence Feeds (AbuseIPDB & VirusTotal)...")
    intel = enrich_ip(c2_ip)
    print(f"          • Abuse Score: {intel['abuse_score']}% | VT Detections: {intel['vt_detections']}")
    print(f"          • Composite Threat Score: {intel['composite_score']}/100 (Verdict: {'THREAT' if intel['is_threat'] else 'BENIGN'})")
    
    # Step 2: Policy Gate & Active Containment
    if intel["is_threat"]:
        print("    [2/3] Threat Policy Threshold Exceeded -> Triggering Active Containment...")
        containment = block_ip_firewall(c2_ip)
        print(f"          [✓] Firewall Outbound Rule Deployed: {containment['rule_name']}")
    else:
        print("    [2/3] Threat Score Below Threshold -> No Active Containment Required.")
        containment = {"status": "NO_ACTION_REQUIRED", "details": "Score within acceptable baseline."}
        
    # Step 3: Dispatch ChatOps Alert
    print("    [3/3] Broadcasting Incident State to Security Operations Queue...")
    send_chatops_alert(alert, intel, containment)
    
    return {
        "alert_id": alert_id,
        "threat_intel": intel,
        "containment": containment
    }
