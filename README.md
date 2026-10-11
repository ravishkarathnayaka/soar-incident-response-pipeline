# Automated SOAR Incident Response & Threat Intelligence Pipeline

An enterprise-grade Security Orchestration, Automation, and Response (SOAR) pipeline engineered in Python. This system automates the end-to-end incident response lifecycle: ingesting SIEM alert telemetry, enriching indicators of compromise (IOCs) across multiple threat intelligence feeds (AbuseIPDB, VirusTotal), evaluating policy risk thresholds, executing automated host containment via local firewall rules, and dispatching real-time ChatOps alerts.

---

## Architecture Overview

```text
               +----------------------------------------+
               |   SIEM Alert / Webhook Trigger: JSON   |
               +----------------------------------------+
                                   |
                                   v
               +----------------------------------------+
               |          1. Ingestion Engine           |
               | (FastAPI REST Webhook / Batch Runner)  |
               |  Extracts: Host, User, Process, C2 IP  |
               +----------------------------------------+
                                   |
                  +----------------+----------------+
                  |                                 |
                  v                                 v
   +------------------------------+  +------------------------------+
   |  2. Threat Intel Enrichment  |  |  3. Context & MITRE Mapping  |
   | • AbuseIPDB API (Confidence) |  | • T1059.001 / T1105 / T1071  |
   | • VirusTotal API (Detections)|  | • Endpoint Asset Criticality |
   +------------------------------+  +------------------------------+
                  |                                 |
                  +----------------+----------------+
                                   |
                                   v
               +----------------------------------------+
               |        4. Policy Decision Gate         |
               |  Is Composite Threat Score >= 60/100?  |
               +----------------------------------------+
                                   |
                  +----------------+----------------+
                  |                                 |
           [ Score >= 60 ]                   [ Score < 60 ]
                  |                                 |
                  v                                 v
   +------------------------------+  +------------------------------+
   |    HIGH-RISK CONTAINMENT     |  |      BENIGN / BASELINE       |
   | • Deploy Windows Firewall    |  | • Allow Network Traffic      |
   |   Rule (New-NetFirewallRule) |  | • Log to Audit Trail         |
   | • Write JSON Audit Record    |  | • Zero Host Disruption       |
   | • Dispatch ChatOps Webhook   |  | • Standard Telemetry Log     |
   +------------------------------+  +------------------------------+
```

---

## Technical Highlights & Key Competencies

* **Multi-Feed Threat Intelligence Fusion:** Engineered an automated enrichment engine that queries AbuseIPDB and VirusTotal APIs in parallel, computing a weighted 0–100 **Composite Threat Score** to eliminate single-source bias.
* **Automated Active Host Containment:** Programmatically deploys outbound network block rules via Windows Defender Firewall (`New-NetFirewallRule`) to immediately sever active command-and-control (C2) communication channels.
* **REST API Webhook Ingestion:** Built an asynchronous **FastAPI** web service (`app.py`) allowing modern SIEM platforms (Splunk, Elastic, Sentinel) and network sensors to trigger automated playbooks via HTTP POST webhooks.
* **Policy-Driven Triage Gate:** Implemented strict decision logic to differentiate verified C2 beaconing (e.g., Cobalt Strike) from benign administrative traffic (e.g., Google Public DNS `8.8.8.8`), preventing operational disruption.
* **Audit Trail & Forensic Compliance:** Generates structured, timestamped JSON containment audit records (`containment_logs/`) documenting rule names, targeted IPs, and execution statuses for incident responders.
* **ChatOps Incident Broadcasting:** Dispatches rich incident embed cards to SOC chat channels (Discord/Slack/Teams) with detection ratios, ISP origin, and mitigation confirmations.

---

## Telemetry & Containment Verification

The pipeline was validated against a multi-vector alert dataset simulating both adversary C2 traffic and legitimate system activity:

### 1. Batch Execution Summary
```text
======================================================================
      AUTOMATED SOAR INCIDENT RESPONSE & CONTAINMENT PIPELINE      
======================================================================

[*] Executing SOAR Playbook for Alert: SEC-SOAR-2026-001
    - Target Endpoint : vm-windows-target
    - Extracted C2 IP : 118.25.6.39
    - Adversary Vector: T1059.001 - PowerShell C2 Beaconing
    [1/3] Querying Threat Intelligence Feeds (AbuseIPDB & VirusTotal)...
          • Abuse Score: 100% | VT Detections: 64/72
          • Composite Threat Score: 100/100 (Verdict: THREAT)
    [2/3] Threat Policy Threshold Exceeded -> Triggering Active Containment...
          [✓] Firewall Outbound Rule Deployed: SOAR_BLOCK_118.25.6.39
    [3/3] Broadcasting Incident State to Security Operations Queue...

[*] Executing SOAR Playbook for Alert: SEC-SOAR-2026-002
    - Target Endpoint : vm-windows-target
    - Extracted C2 IP : 192.168.1.100
    - Adversary Vector: T1105 - Ingress Tool Transfer
    [1/3] Querying Threat Intelligence Feeds (AbuseIPDB & VirusTotal)...
          • Abuse Score: 92% | VT Detections: 58/72
          • Composite Threat Score: 96/100 (Verdict: THREAT)
    [2/3] Threat Policy Threshold Exceeded -> Triggering Active Containment...
          [✓] Firewall Outbound Rule Deployed: SOAR_BLOCK_192.168.1.100
    [3/3] Broadcasting Incident State to Security Operations Queue...

[*] Executing SOAR Playbook for Alert: SEC-SOAR-2026-003
    - Target Endpoint : vm-windows-target
    - Extracted C2 IP : 8.8.8.8
    - Adversary Vector: T1071 - Standard DNS Query
    [1/3] Querying Threat Intelligence Feeds (AbuseIPDB & VirusTotal)...
          • Abuse Score: 0% | VT Detections: 0/72
          • Composite Threat Score: 0/100 (Verdict: BENIGN)
    [2/3] Threat Score Below Threshold -> No Active Containment Required.

======================================================================
                 SOAR EXECUTION BATCH SUMMARY                 
======================================================================
 • Total Alerts Ingested : 3
 • High-Risk C2s Blocked : 2
 • Benign Events Allowed : 1
 • Containment Audit Logs: Check the 'containment_logs/' directory
======================================================================
```

### 2. Generated Containment Audit Record
Example audit log (`containment_logs/containment_118_25_6_39.json`):
```json
{
  "timestamp": "2026-10-11T09:12:59.856944Z",
  "action": "FIREWALL_BLOCK",
  "target_ip": "118.25.6.39",
  "rule_name": "SOAR_BLOCK_118.25.6.39",
  "status": "SUCCESS",
  "details": "Outbound network communication to 118.25.6.39 blocked across all profiles."
}
```

---

## Repository Structure

```text
soar-incident-response-pipeline/
├── sample_alerts/                         # Simulated SIEM alert payloads
│   ├── SEC-SOAR-2026-001.json             # Cobalt Strike C2 beacon alert
│   ├── SEC-SOAR-2026-002.json             # Ingress tool transfer / rogue stager alert
│   └── SEC-SOAR-2026-003.json             # Benign Google DNS resolution event
├── containment_logs/                      # Immutable containment audit trail
│   ├── containment_118_25_6_39.json       # Audit record for blocked Cobalt Strike C2
│   └── containment_192_168_1_100.json     # Audit record for blocked rogue stager IP
├── threat_intel.py                        # Threat intel enrichment (VirusTotal & AbuseIPDB APIs)
├── containment.py                         # Active mitigation engine (Windows Firewall rules)
├── notifier.py                            # ChatOps webhook alerting engine (Discord/Slack)
├── playbook.py                            # Core SOAR decision gate & orchestration logic
├── app.py                                 # FastAPI REST webhook receiver for live SIEM alerts
├── make_sample_alerts.py                  # Alert telemetry generator
├── run_pipeline.py                        # Batch orchestration runner
├── requirements.txt                       # Project dependencies
└── README.md                              # Technical documentation
```

---

## Getting Started & Execution

### Prerequisites
* Python 3.10+
* Virtual Environment (`venv`)
* Windows PowerShell (Run as Administrator for live firewall rule deployment)

### 1. Setup & Installation
```bash
git clone https://github.com/ravishkarathnayaka/soar-incident-response-pipeline.git
cd soar-incident-response-pipeline

python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure Threat Intel Keys (Optional)
Create a `.env` file in the root directory (the pipeline automatically uses built-in high-fidelity threat intelligence cache if keys are omitted):
```ini
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
DISCORD_WEBHOOK_URL=your_discord_webhook_url_here
```

### 3. Run the Batch Playbook Runner
```bash
python run_pipeline.py
```

### 4. Run the Live Webhook Receiver
Launch the FastAPI webhook listener to accept real-time HTTP POST alerts from SIEMs:
```bash
uvicorn app:app --reload --port 8000
```
Test the webhook endpoint:
```bash
curl -X POST http://localhost:8000/webhook/alert \
     -H "Content-Type: application/json" \
     -d '{"alert_id": "TEST-001", "host": "vm-windows-target", "c2_ip": "118.25.6.39", "technique": "T1059"}'
```
