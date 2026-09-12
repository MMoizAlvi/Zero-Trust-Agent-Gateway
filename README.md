# Zero Trust AI Agent Gateway

> **Architectural Paradigm:** Cryptographic Non-Human Identity (NHI) Attestation, Policy-as-Code (PaC) Enforcement, and Immutable Audit Trails for Autonomous LLM Tool Invocation.

---

## 1. Abstract & Problem Statement

As Autonomous AI Agents and Large Language Model (LLM) tool-use frameworks (e.g., LangChain, AutoGen, CrewAI) gain operational authority over enterprise infrastructure, traditional perimeter defense mechanisms fail. Standard API security paradigms assume static human user sessions or long-lived API keys. When applied to dynamic, probabilistic AI agents, these paradigms introduce severe security vectors:

* **Identity Confusion & Token Escalation:** Autonomous agents operating under coarse-grained corporate credentials can be coerced via Indirect Prompt Injection (IPI) to execute unauthorized downstream actions.
* **Lack of Dynamic Policy Enforcement:** Static Role-Based Access Control (RBAC) cannot evaluate execution-time context, such as parameter boundaries, action velocities, or intent shifts.
* **Audit Blindspots:** Non-Deterministic agent behavior produces opaque execution logs, making forensic post-mortems and compliance verification (e.g., SOC2, ISO 27001) impossible.

**Zero Trust AI Agent Gateway** bridges this gap by inserting an asymmetric cryptographic enforcement proxy between autonomous agents and enterprise tool APIs. The architecture enforces **Least Privilege at Execution Time**, validating agent cryptographic signatures and parsing action payloads against dynamic deterministic policies before upstream forward routing occurs.

---

## 2. Core Security Architecture

The system enforces a **Policy Decision Point (PDP) / Policy Enforcement Point (PEP)** segregation model operating across four distinct verification phases:

### Architectural Principles

1. **Cryptographic Identity Attestation (RS256):** Agents are provisioned short-lived Ephemeral Non-Human Identity (NHI) tokens signed via asymmetric RSA-2048 keypairs. Upstream tools never handle raw private keys.
2. **Deterministic Fine-Grained Policy Evaluation:** The gateway interceptor acts as an explicit boundary guard. Even if an LLM is compromised via indirect prompt injection, downstream operations exceeding fine-grained thresholds (e.g., transaction limits > \$500) are rejected at the proxy layer.
3. **Structured Forensic Audit Evidence:** Every request—whether authorized, rejected, or unauthenticated—emits a machine-readable JSON log record containing agent subject claims, action paths, payload parameters, and evaluation rationale.

---

## 3. Threat Model & Mitigation Matrix

| Threat Vector | Mechanism / Exploit | Gateway Mitigation Strategy |
| :--- | :--- | :--- |
| **Indirect Prompt Injection (IPI)** | Malicious data payloads hijack LLM reasoning, prompting unauthorized API calls. | **Payload Constraint Inspection:** Policies inspect parameter state (e.g., financial value thresholds) independently of LLM intent. |
| **Identity Impersonation** | Rogue agent process attempts to invoke administrative endpoints. | **Asymmetric Token Verification:** Mandatory RS256 public-key attestation of `sub` and `role` claims. |
| **Privilege Escalation** | Low-privilege (Analytics) agent attempts modification operations (POST/DELETE). | **Endpoint RBAC Boundary:** Strict verb/path matching matrices enforced prior to proxy routing. |
| **Replay & Stale Token Attacks** | Captured agent bearer tokens reused for unauthorized calls. | **Cryptographic Expiry Check:** Short-lived JWT claims strictly enforced via clock skew checks. |

---

## Installation & Setup

### Prerequisites

* **Python:** Version 3.10 or higher
* **Open Policy Agent (OPA):** CLI binary installed and accessible in system `PATH` or placed in the project root directory as `opa.exe`

---

## Start & Execution

### 1. Environment Setup & Key Generation

```powershell
# Navigate to project root
cd zero-trust-agent-gateway

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Generate RSA-2048 keypair (private_key.pem & public_key.pem)
python test_agent/generate_tokens.py

# Terminal 1: Upstream Mock Target API (Port 8080)
python mock_upstream/server.py

# Terminal 2: Open Policy Agent Engine (Port 8181)
.\opa.exe run --server --addr :8181 policy.rego

# Terminal 3: Zero Trust FastAPI Gateway PEP (Port 8000)
python -m uvicorn app.main:app --port 8000 --reload

# Terminal 4: Execute 5-Scenario Automated Validation Harness
python test_agent/agent_simulation.py
