import httpx
from typing import Tuple, Dict, Any

OPA_SERVER_URL = "http://127.0.0.1:8181/v1/data/agent/authz"

class OPAPolicyEngine:
    @classmethod
    async def evaluate(
        cls, token: str, method: str, path: str, payload: Dict[str, Any]
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Queries the OPA engine with request context."""
        
        # Prepare input document expected by Rego policy
        opa_input = {
            "input": {
                "token": token,
                "method": method,
                "path": path,
                "payload": payload or {}
            }
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(OPA_SERVER_URL, json=opa_input, timeout=2.0)
                
                if response.status_code != 200:
                    return False, f"OPA Engine Error: HTTP {response.status_code}", {"agent_id": "UNKNOWN", "role": "UNKNOWN"}
                
                result = response.json().get("result", {})
                
                allowed = result.get("allow", False)
                reason = result.get("reason", "No explicit allow rule matched")
                agent_info = result.get("agent_info", {"agent_id": "UNKNOWN", "role": "UNKNOWN"})

                return allowed, reason, agent_info

        except httpx.RequestError as exc:
            return False, f"OPA Service Unreachable: {str(exc)}", {"agent_id": "UNKNOWN", "role": "UNKNOWN"}
            