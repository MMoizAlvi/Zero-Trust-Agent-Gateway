from fastapi import FastAPI, Request, Response, HTTPException
import httpx
from app.core.auth import AuthEngine
from app.core.policy import PolicyEngine
from app.core.audit import log_audit_event

# THIS IS THE MISSING ATTRIBUTE: 'app'
app = FastAPI(title="Zero Trust AI Gateway", version="1.0.0")

auth_engine = AuthEngine()
UPSTREAM_TARGET = "http://127.0.0.1:8080"  # Target Upstream API Service

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def gateway_proxy(request: Request, path: str):
    full_path = f"/{path}"
    method = request.method
    
    # Extract Body Payload if present
    payload = {}
    if method in ["POST", "PUT"]:
        try:
            payload = await request.json()
        except Exception:
            payload = {}

    # 1. Cryptographic Identity Verification
    auth_header = request.headers.get("Authorization")
    try:
        claims = auth_engine.verify_agent_token(auth_header)
    except HTTPException as exc:
        log_audit_event(
            agent_id="UNKNOWN",
            role="UNAUTHENTICATED",
            method=method,
            path=full_path,
            decision="DENY",
            reason=exc.detail,
            payload=payload
        )
        return Response(
            content=f'{{"error": "Unauthorized", "detail": "{exc.detail}"}}',
            status_code=exc.status_code,
            media_type="application/json"
        )

    agent_id = claims.get("sub", "UNKNOWN_AGENT")
    role = claims.get("role", "UNASSIGNED")

    # 2. Policy-as-Code Evaluation
    allowed, reason = PolicyEngine.evaluate(
        agent_claims=claims,
        method=method,
        path=full_path,
        payload=payload
    )

    # 3. Write Audit Evidence
    decision_label = "ALLOW" if allowed else "DENY"
    log_audit_event(
        agent_id=agent_id,
        role=role,
        method=method,
        path=full_path,
        decision=decision_label,
        reason=reason,
        payload=payload
    )

    # 4. Enforce Boundary Block
    if not allowed:
        return Response(
            content=f'{{"error": "Forbidden", "policy_reason": "{reason}"}}',
            status_code=403,
            media_type="application/json"
        )

    # 5. Forward Authorized Traffic to Upstream API
    async with httpx.AsyncClient() as client:
        try:
            upstream_resp = await client.request(
                method=method,
                url=f"{UPSTREAM_TARGET}{full_path}",
                headers={"X-Authenticated-Agent": agent_id, "X-Agent-Role": role},
                json=payload if payload else None
            )
            return Response(
                content=upstream_resp.content,
                status_code=upstream_resp.status_code,
                headers=dict(upstream_resp.headers)
            )
        except httpx.RequestError as err:
            return Response(
                content=f'{{"error": "Bad Gateway", "detail": "Upstream service unreachable: {str(err)}"}}',
                status_code=502,
                media_type="application/json"
            )