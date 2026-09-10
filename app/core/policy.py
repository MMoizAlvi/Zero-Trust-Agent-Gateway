class PolicyEngine:
    """
    In-memory Policy Decision Point (PDP) simulating fine-grained OPA Rego rules.
    Enforces Least Privilege and Parameter-Level Constraints.
    """

    @staticmethod
    def evaluate(agent_claims: dict, method: str, path: str, payload: dict) -> tuple[bool, str]:
        role = agent_claims.get("role")
        agent_id = agent_claims.get("sub")

        # 1. Reject unknown or unassigned roles
        if not role:
            return False, "Deny: Token lacks assigned agent role claim"

        # 2. Rule Set for Read-Only Analytics Agents
        if role == "analytics_agent":
            if method == "GET" and path.startswith("/api/v1/metrics"):
                return True, "Allow: Analytics agent authorized for metrics read"
            return False, f"Deny: Role '{role}' forbidden from performing {method} on {path}"

        # 3. Rule Set for Execution Agents (Restricted Action Execution)
        if role == "execution_agent":
            if path == "/api/v1/execute-transaction":
                if method != "POST":
                    return False, f"Deny: Invalid method {method} for execution path"
                
                # Payload Parameter Inspection
                amount = payload.get("amount", 0)
                if not isinstance(amount, (int, float)):
                    return False, "Deny: Malformed transaction amount parameter"
                
                if amount > 500:
                    return False, f"Deny: Transaction amount (${amount}) exceeds threshold limit ($500)"
                
                return True, "Allow: Execution parameters verified within threshold"
            
            if method == "GET":
                return True, "Allow: Execution agent read access permitted"

        return False, f"Deny: No matching policy allowing {role} to execute {method} {path}"