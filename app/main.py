from pathlib import Path
from fastapi import FastAPI, Request, Response
import httpx
import jwt
from app.opa_client import OPAPolicyEngine
from app.core.audit import log_audit_event

app = FastAPI(title="Zero Trust AI Gateway (RS256 & OPA Integrated)")
UPSTREAM_URL = "http://127.0.0.1:8080"

BASE_DIR = Path(__file__).resolve().parent.parent
PUBLIC_KEY_PATH = BASE_DIR / "public_key.pem"

# Load Public Key for RS256 Verification from Root Directory
try:
    with open(PUBLIC_KEY_PATH, "r") as f:
        PUBLIC_KEY = f.read()
except FileNotFoundError:
    PUBLIC_KEY = None

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def reverse_proxy(request: Request, path: str):
    # 1. Extract Bearer Token
    auth_header = request.headers.get("Authorization", "")
    raw_token = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""

    if not raw_token:
        log_audit_event("UNKNOWN", "UNKNOWN", f"{request.method} /{path}", "DENY", "Missing Authorization Token", {})
        return Response(
            content='{"error": "Unauthorized", "reason": "Missing bearer token"}',
            status_code=401,
            media_type="application/json"
        )

    if not PUBLIC_KEY:
        log_audit_event("UNKNOWN", "UNKNOWN", f"{request.method} /{path}", "DENY", "Public key missing on gateway", {})
        return Response(
            content='{"error": "Unauthorized", "reason": "Gateway missing public key configuration"}',
            status_code=401,
            media_type="application/json"
        )

    # 2. RS256 Attestation Signature Check
    try:
        decoded_payload = jwt.decode(
            raw_token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            options={"verify_iss": True},
            issuer="zero-trust-auth-server"
        )
        agent_id = decoded_payload.get("sub")
        role = decoded_payload.get("role")
    except jwt.PyJWTError as exc:
        log_audit_event("UNKNOWN", "UNKNOWN", f"{request.method} /{path}", "DENY", f"RS256 Attestation Failed: {str(exc)}", {})
        return Response(
            content=f'{{"error": "Unauthorized", "reason": "Invalid or forged JWT signature: {str(exc)}"}}',
            status_code=401,
            media_type="application/json"
        )

    # 3. Extract Body Payload (if POST/PUT)
    payload = {}
    if request.method in ["POST", "PUT"]:
        try:
            payload = await request.json()
        except Exception:
            payload = {}

    full_path = f"/{path}"

    # 4. Query OPA Engine with Token & Payload Context
    allowed, reason, opa_agent_info = await OPAPolicyEngine.evaluate(
        token=raw_token,
        method=request.method,
        path=full_path,
        payload=payload
    )

    agent_info = {"agent_id": agent_id, "role": role}

    # 5. Record Audit Log Entry
    log_audit_event(
        agent_id=agent_info["agent_id"],
        role=agent_info["role"],
        action=f"{request.method} {full_path}",
        decision="ALLOW" if allowed else "DENY",
        reason=reason,
        payload=payload
    )

    # 6. Enforce Policy Decision
    if not allowed:
        return Response(
            content=f'{{"error": "Forbidden", "reason": "{reason}"}}',
            status_code=403,
            media_type="application/json"
        )

    # 7. Forward Authorized Request Upstream
    async with httpx.AsyncClient() as client:
        upstream_req = client.build_request(
            method=request.method,
            url=f"{UPSTREAM_URL}{full_path}",
            headers={"X-Agent-ID": agent_info["agent_id"]},
            json=payload if payload else None
        )
        upstream_resp = await client.send(upstream_req)

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=dict(upstream_resp.headers)
    )
