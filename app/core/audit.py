import logging
import json
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("zero_trust_audit")

def log_audit_event(agent_id: str, role: str, method: str, path: str, decision: str, reason: str, payload: dict = None):
    audit_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "identity": {
            "agent_id": agent_id or "ANONYMOUS",
            "role": role or "UNASSIGNED",
            "type": "Non-Human Identity (NHI)"
        },
        "request": {
            "method": method,
            "path": path,
            "payload_summary": payload or {}
        },
        "verdict": {
            "decision": decision,
            "reason": reason
        }
    }
    logger.info(json.dumps(audit_record))