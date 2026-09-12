from fastapi import FastAPI, Request, Response
import httpx
from app.opa_client import OPAPolicyEngine
from app.core.audit import log_audit_event

app = FastAPI(title="Zero Trust AI Gateway (OPA Integrated)")
UPSTREAM_URL = "http://127.0.0.1:8080"

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def reverse_proxy(request: Request, path: str):
    # 1. Extract Bearer Token
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""

    # 2. Parse Body Payload
    payload = {}
    if request.method in ["POST", "PUT"]:
        try:
            payload = await request.json()
        except Exception:
            payload = {}

    full_path = f"/{path}"

    # 3. Asynchronously Query OPA Engine
    allowed, reason, agent_info = await OPAPolicyEngine.evaluate(
        token=token,
        method=request.method,
        path=full_path,
        payload=payload
    )

    # 4. Structured Audit Log
    log_audit_event(
        agent_id=agent_info.get("agent_id"),
        role=agent_info.get("role"),
        action=f"{request.method} {full_path}",
        decision="ALLOW" if allowed else "DENY",
        reason=reason,
        payload=payload
    )

    # 5. Enforce Decision
    if not allowed:
        return Response(
            content=f'{{"error": "Forbidden", "reason": "{reason}"}}',
            status_code=403,
            media_type="application/json"
        )

    # 6. Forward Authorized Request Upstream
    async with httpx.AsyncClient() as client:
        upstream_req = client.build_request(
            method=request.method,
            url=f"{UPSTREAM_URL}{full_path}",
            headers={"X-Agent-ID": agent_info.get("agent_id")},
            json=payload if payload else None
        )
        upstream_resp = await client.send(upstream_req)

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=dict(upstream_resp.headers)
    )
