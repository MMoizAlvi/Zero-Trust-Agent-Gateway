import jwt
from pathlib import Path
from fastapi import HTTPException, status

PUBLIC_KEY_PATH = Path("certs/public_key.pem")

class AuthEngine:
    def __init__(self):
        if not PUBLIC_KEY_PATH.exists():
            raise FileNotFoundError("Public key missing. Run key generation phase first.")
        self.public_key = PUBLIC_KEY_PATH.read_text()

    def verify_agent_token(self, auth_header: str) -> dict:
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or malformed Authorization header"
            )

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=["RS256"],
                options={"verify_aud": False}
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Non-Human Identity token has expired"
            )
        except jwt.InvalidTokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Cryptographic identity verification failed: {str(e)}"
            )
