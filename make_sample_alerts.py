import json
import os

os.makedirs("sample_alerts", exist_ok=True)

alerts = [
    {
        "alert_id": "SEC-SOAR-2026-001",
        "timestamp": "2026-10-11T09:15:00Z",
        "host": "vm-windows-target",
        "user": "azureuser",
        "process_name": "powershell.exe",
        "technique": "T1059.001 - PowerShell C2 Beaconing",
        "c2_ip": "118.25.6.39",
        "description": "Outbound HTTP beacon detected to known Cobalt Strike infrastructure."
    },
    {
        "alert_id": "SEC-SOAR-2026-002",
        "timestamp": "2026-10-11T09:16:30Z",
        "host": "vm-windows-target",
        "user": "azureuser",
        "process_name": "rundll32.exe",
        "technique": "T1105 - Ingress Tool Transfer",
        "c2_ip": "192.168.1.100",
        "description": "Suspicious remote script cradle download attempted from rogue IP."
    },
    {
        "alert_id": "SEC-SOAR-2026-003",
        "timestamp": "2026-10-11T09:18:00Z",
        "host": "vm-windows-target",
        "user": "SYSTEM",
        "process_name": "svchost.exe",
        "technique": "T1071 - Standard DNS Query",
        "c2_ip": "8.8.8.8",
        "description": "Legitimate DNS resolution request to public provider."
    }
]

for alert in alerts:
    file_path = os.path.join("sample_alerts", f"{alert['alert_id']}.json")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(alert, f, indent=2)

print("[✓] Sample alert files generated in sample_alerts/")
