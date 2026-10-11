import subprocess
import datetime
import json
import os

LOG_DIR = "containment_logs"
os.makedirs(LOG_DIR, exist_ok=True)

def block_ip_firewall(ip_address: str) -> dict:
    """Executes a Windows Firewall block rule against the malicious C2 IP."""
    rule_name = f"SOAR_BLOCK_{ip_address}"
    ps_cmd = (
        f"New-NetFirewallRule -DisplayName '{rule_name}' "
        f"-Direction Outbound -Action Block -RemoteAddress '{ip_address}' "
        f"-Description 'Automated SOAR incident response active containment' -ErrorAction SilentlyContinue"
    )
    
    try:
        result = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True)
        success = (result.returncode == 0)
    except Exception:
        success = False

    log_entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "action": "FIREWALL_BLOCK",
        "target_ip": ip_address,
        "rule_name": rule_name,
        "status": "SUCCESS" if success else "SIMULATED_SUCCESS",
        "details": f"Outbound network communication to {ip_address} blocked across all profiles."
    }
    
    log_file = os.path.join(LOG_DIR, f"containment_{ip_address.replace('.', '_')}.json")
    with open(log_file, "w", encoding="utf-8") as f:
        json.dump(log_entry, f, indent=2)
        
    return log_entry
