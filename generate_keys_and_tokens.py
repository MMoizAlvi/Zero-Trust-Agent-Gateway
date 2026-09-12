import jwt
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Points to zero-trust-agent-gateway/ whether run from root or test_agent/
BASE_DIR = Path(__file__).resolve().parent.parent if Path(__file__).resolve().parent.name == "test_agent" else Path(__file__).resolve().parent

PUBLIC_KEY_PATH = BASE_DIR / "public_key.pem"
PRIVATE_KEY_PATH = BASE_DIR / "private_key.pem"

# 2. Generate RSA Key Pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

pem_public = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# 3. Save Key Files directly in the Root Directory
with open(PUBLIC_KEY_PATH, "w") as f:
    f.write(pem_public)

with open(PRIVATE_KEY_PATH, "w") as f:
    f.write(pem_private)

print(f"--- RSA256 PUBLIC KEY SAVED TO {PUBLIC_KEY_PATH} ---")
print(f"--- RSA256 PRIVATE KEY SAVED TO {PRIVATE_KEY_PATH} ---")

# 4. Generate Signed Test JWTs
def create_token(agent_id: str, role: str) -> str:
    payload = {
        "sub": agent_id,
        "role": role,
        "iss": "zero-trust-auth-server",
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)
    }
    return jwt.encode(payload, pem_private, algorithm="RS256")

token_analytics = create_token("agent-01", "analytics_agent")
token_execution = create_token("agent-02", "execution_agent")

print("\n--- GENERATED RS256 TOKENS ---")
print(f"ANALYTICS_TOKEN = \"{token_analytics}\"")
print(f"EXECUTION_TOKEN = \"{token_execution}\"")
