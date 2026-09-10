import jwt
import httpx
from datetime import datetime, timedelta, timezone
from pathlib import Path

PRIVATE_KEY = Path("certs/private_key.pem").read_text()
GATEWAY_URL = "http://127.0.0.1:8000"

def create_jwt(agent_id: str, role: str, expires_in_minutes: int = 15) -> str:
    payload = {
        "sub": agent_id,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

def run_suite():
    print("=================================================================")
    print(" RUNNING ZERO TRUST AI AGENT GATEWAY SECURITY VERIFICATION SUITE")
    print("=================================================================\n")

    analytics_token = create_jwt(agent_id="agent-analytics-01", role="analytics_agent")
    execution_token = create_jwt(agent_id="agent-exec-02", role="execution_agent")

    # TEST 1: Unauthenticated Call
    print("[TEST 1] Sending request with NO authorization token...")
    res = httpx.get(f"{GATEWAY_URL}/api/v1/metrics")
    print(f"Result: HTTP {res.status_code} | Response: {res.text}\n")

    # TEST 2: Analytics Agent Reads Metrics (Valid Action)
    print("[TEST 2] Analytics Agent requesting GET /api/v1/metrics...")
    res = httpx.get(
        f"{GATEWAY_URL}/api/v1/metrics",
        headers={"Authorization": f"Bearer {analytics_token}"}
    )
    print(f"Result: HTTP {res.status_code} | Response: {res.text}\n")

    # TEST 3: Analytics Agent Attempts Transaction Execution (Role Boundary Breach)
    print("[TEST 3] Analytics Agent attempting POST /api/v1/execute-transaction...")
    res = httpx.post(
        f"{GATEWAY_URL}/api/v1/execute-transaction",
        headers={"Authorization": f"Bearer {analytics_token}"},
        json={"amount": 100}
    )
    print(f"Result: HTTP {res.status_code} | Response: {res.text}\n")

    # TEST 4: Execution Agent Executing Out-of-Bounds Payload ($2,500 > $500 Limit)
    print("[TEST 4] Execution Agent attempting transaction of $2,500 (Exceeds Policy Limit)...")
    res = httpx.post(
        f"{GATEWAY_URL}/api/v1/execute-transaction",
        headers={"Authorization": f"Bearer {execution_token}"},
        json={"amount": 2500}
    )
    print(f"Result: HTTP {res.status_code} | Response: {res.text}\n")

    # TEST 5: Execution Agent Executing Authorized Transaction ($300 <= $500 Limit)
    print("[TEST 5] Execution Agent attempting transaction of $300 (Within Policy Limit)...")
    res = httpx.post(
        f"{GATEWAY_URL}/api/v1/execute-transaction",
        headers={"Authorization": f"Bearer {execution_token}"},
        json={"amount": 300}
    )
    print(f"Result: HTTP {res.status_code} | Response: {res.text}\n")

if __name__ == "__main__":
    run_suite()