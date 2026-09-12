import json
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("audit_logger")

def log_audit_event(agent_id: str, role: str, action: str, decision: str, reason: str, payload: dict):
    """
    Outputs structured JSON log records for compliance and audit analysis.
    """
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "agent_id": agent_id or "UNKNOWN",
        "role": role or "UNKNOWN",
        "action": action,
        "decision": decision,
        "reason": reason,
        "payload": payload
    }
    logger.info(json.dumps(event))
