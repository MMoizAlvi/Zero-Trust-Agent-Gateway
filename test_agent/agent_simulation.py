import httpx
import jwt
from pathlib import Path
from datetime import datetime, timedelta, timezone

# Resolve project root path dynamically
BASE_DIR = Path(__file__).resolve().parent.parent
PRIVATE_KEY_PATH = BASE_DIR / "private_key.pem"

# Load static Private Key for signing test JWTs
with open(PRIVATE_KEY_PATH, "r") as f:
    PRIVATE_KEY = f.read()

def get_jwt(agent_id: str, role: str) -> str:
    payload = {
        "sub": agent_id,
        "role": role,
        "iss": "zero-trust-auth-server",
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

ANALYTICS_TOKEN = get_jwt("agent-01", "analytics_agent")
EXECUTION_TOKEN = get_jwt("agent-02", "execution_agent")

GATEWAY_URL = "http://127.0.0.1:8000"

def run_tests():
    print("--- STARTING ZERO TRUST GATEWAY AGENT TESTS ---\n")

    # Test 1: Analytics Agent -> GET /api/analytics (ALLOW - 200)
    print("[TEST 1] Analytics Agent -> GET /api/analytics")
    resp = httpx.get(
        f"{GATEWAY_URL}/api/analytics",
        headers={"Authorization": f"Bearer {ANALYTICS_TOKEN}"}
    )
    print(f"Status Code: {resp.status_code}")
    print(f"Response:    {resp.text}\n")

    # Test 2: Analytics Agent -> POST /api/transaction ($500) (DENY - 403)
    print("[TEST 2] Analytics Agent -> POST /api/transaction ($500)")
    resp = httpx.post(
        f"{GATEWAY_URL}/api/transaction",
        headers={"Authorization": f"Bearer {ANALYTICS_TOKEN}"},
        json={"amount": 500}
    )
    print(f"Status Code: {resp.status_code}")
    print(f"Response:    {resp.text}\n")

    # Test 3: Execution Agent -> POST /api/transaction ($500) (ALLOW - 200)
    print("[TEST 3] Execution Agent -> POST /api/transaction ($500)")
    resp = httpx.post(
        f"{GATEWAY_URL}/api/transaction",
        headers={"Authorization": f"Bearer {EXECUTION_TOKEN}"},
        json={"amount": 500}
    )
    print(f"Status Code: {resp.status_code}")
    print(f"Response:    {resp.text}\n")

    # Test 4: Execution Agent -> POST /api/transaction ($1500) (DENY - 403)
    print("[TEST 4] Execution Agent -> POST /api/transaction ($1500)")
    resp = httpx.post(
        f"{GATEWAY_URL}/api/transaction",
        headers={"Authorization": f"Bearer {EXECUTION_TOKEN}"},
        json={"amount": 1500}
    )
    print(f"Status Code: {resp.status_code}")
    print(f"Response:    {resp.text}\n")

    # Test 5: Unsigned / Malformed Token (DENY - 401)
    print("[TEST 5] Unsigned / Malformed Token")
    resp = httpx.get(
        f"{GATEWAY_URL}/api/analytics",
        headers={"Authorization": "Bearer invalid-token-string"}
    )
    print(f"Status Code: {resp.status_code}")
    print(f"Response:    {resp.text}\n")

if __name__ == "__main__":
    run_tests()
    