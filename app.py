from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from playbook import run_containment_playbook

app = FastAPI(
    title="Automated SecOps SOAR Incident Response Webhook",
    description="Orchestrates automated threat intelligence lookups and network containment playbooks.",
    version="1.0.0"
)

class SecurityAlert(BaseModel):
    alert_id: str
    host: str
    user: Optional[str] = "SYSTEM"
    process_name: Optional[str] = "unknown"
    technique: Optional[str] = "Unspecified MITRE Technique"
    c2_ip: str
    description: Optional[str] = "SIEM triggered alert"

@app.get("/")
def health_check():
    return {"status": "ONLINE", "service": "SOAR Incident Responder Engine"}

@app.post("/webhook/alert")
def receive_alert(alert: SecurityAlert):
    """Receives incoming SIEM alerts and executes the containment playbook."""
    try:
        result = run_containment_playbook(alert.dict())
        return {
            "status": "PROCESSED",
            "alert_id": alert.alert_id,
            "action_taken": result["containment"]["status"],
            "details": result["containment"]["details"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
