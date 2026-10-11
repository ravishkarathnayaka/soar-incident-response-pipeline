import os
import json
import glob
from playbook import run_containment_playbook

def main():
    print("=" * 70)
    print("      AUTOMATED SOAR INCIDENT RESPONSE & CONTAINMENT PIPELINE      ")
    print("=" * 70)
    
    alert_files = sorted(glob.glob("sample_alerts/*.json"))
    if not alert_files:
        print("[-] No alert files found in sample_alerts/ directory.")
        return

    summary_stats = {"processed": 0, "contained": 0, "benign": 0}

    for file_path in alert_files:
        with open(file_path, "r", encoding="utf-8") as f:
            alert = json.load(f)
            
        result = run_containment_playbook(alert)
        summary_stats["processed"] += 1
        
        if result["containment"].get("status") in ["SUCCESS", "SIMULATED_SUCCESS"]:
            summary_stats["contained"] += 1
        else:
            summary_stats["benign"] += 1

    print("\n" + "=" * 70)
    print("                 SOAR EXECUTION BATCH SUMMARY                 ")
    print("=" * 70)
    print(f" • Total Alerts Ingested : {summary_stats['processed']}")
    print(f" • High-Risk C2s Blocked : {summary_stats['contained']}")
    print(f" • Benign Events Allowed : {summary_stats['benign']}")
    print(f" • Containment Audit Logs: Check the 'containment_logs/' directory")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    main()
