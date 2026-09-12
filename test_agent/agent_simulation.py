import httpx
import time

GATEWAY_URL = "http://127.0.0.1:8000"

def run_tests():
    print("--- STARTING ZERO TRUST GATEWAY AGENT TESTS ---\n")

    # Test 1: Analytics Agent tries GET /api/analytics (Should ALLOW)
    print("[TEST 1] Analytics Agent -> GET /api/analytics")
    resp = httpx.get(
        f"{GATEWAY_URL}/api/analytics",
        headers={"Authorization": "Bearer token-analytics-123"}
    )
    print(f"Status Code: {resp.status_code}")
    print(f"Response:    {resp.text}\n")

    # Test 2: Analytics Agent tries POST /api/transaction (Should DENY)
    print("[TEST 2] Analytics Agent -> POST /api/transaction ($500)")
    resp = httpx.post(
        f"{GATEWAY_URL}/api/transaction",
        headers={"Authorization": "Bearer token-analytics-123"},
        json={"amount": 500}
    )
    print(f"Status Code: {resp.status_code}")
    print(f"Response:    {resp.text}\n")

    # Test 3: Execution Agent tries POST /api/transaction ($500) (Should ALLOW)
    print("[TEST 3] Execution Agent -> POST /api/transaction ($500)")
    resp = httpx.post(
        f"{GATEWAY_URL}/api/transaction",
        headers={"Authorization": "Bearer token-execution-456"},
        json={"amount": 500}
    )
    print(f"Status Code: {resp.status_code}")
    print(f"Response:    {resp.text}\n")

    # Test 4: Execution Agent tries POST /api/transaction ($1500 - exceeds limit) (Should DENY)
    print("[TEST 4] Execution Agent -> POST /api/transaction ($1500)")
    resp = httpx.post(
        f"{GATEWAY_URL}/api/transaction",
        headers={"Authorization": "Bearer token-execution-456"},
        json={"amount": 1500}
    )
    print(f"Status Code: {resp.status_code}")
    print(f"Response:    {resp.text}\n")

if __name__ == "__main__":
    run_tests()
    