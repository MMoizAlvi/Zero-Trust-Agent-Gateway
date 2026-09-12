package agent.authz

import rego.v1

default allow = false
default reason = "Default deny policy enforced"

# Decode JWT token passed from Gateway input
parsed_jwt := io.jwt.decode(input.token)
claims := parsed_jwt[1]

# Extract Agent Identity Claims
active_agent = {
    "agent_id": object.get(claims, "sub", "UNKNOWN"),
    "role": object.get(claims, "role", "UNKNOWN")
}

agent_info = active_agent

# Rule 1: Analytics Agent -> Read-only access
allow if {
    active_agent.role == "analytics_agent"
    input.method == "GET"
}

reason = "Analytics agent granted read-only access" if {
    active_agent.role == "analytics_agent"
    input.method == "GET"
}

# Rule 2: Execution Agent -> GET access allowed
allow if {
    active_agent.role == "execution_agent"
    input.method == "GET"
}

# Rule 3: Execution Agent -> POST transaction within limit (<= $1000)
allow if {
    active_agent.role == "execution_agent"
    input.method == "POST"
    input.path == "/api/transaction"
    input.payload.amount <= 1000
}

reason = "Execution payload authorized" if {
    active_agent.role == "execution_agent"
    input.method == "POST"
    input.path == "/api/transaction"
    input.payload.amount <= 1000
}

# Explicit Denial Reasons
reason = sprintf("Transaction amount ($%d) exceeds threshold limit of $1000", [input.payload.amount]) if {
    active_agent.role == "execution_agent"
    input.method == "POST"
    input.path == "/api/transaction"
    input.payload.amount > 1000
}

reason = sprintf("Analytics agent forbidden from executing %s requests", [input.method]) if {
    active_agent.role == "analytics_agent"
    input.method != "GET"
}
