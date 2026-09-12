package agent.authz

import rego.v1

default allow = false
default reason = "Default deny policy enforced"

# Mapping Bearer Tokens to Agent Identities & Roles
known_agents := {
    "token-analytics-123": {"agent_id": "agent-01", "role": "analytics_agent"},
    "token-execution-456": {"agent_id": "agent-02", "role": "execution_agent"}
}

# Helper rule to resolve active agent context
active_agent = known_agents[input.token]

# Helper to expose agent metadata back to Gateway
agent_info = {
    "agent_id": object.get(active_agent, "agent_id", "UNKNOWN"),
    "role": object.get(active_agent, "role", "UNKNOWN")
}

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

# Rule 3: Execution Agent -> POST transaction within spending limit (<= $1000)
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

# Specific Denial Reasons for Audit Logging
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
