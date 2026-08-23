import time
import json
import base64
import hmac
import hashlib
from typing import Dict, Any

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def _b64url_decode(data: str) -> bytes:
    padding = '=' * (4 - (len(data) % 4)) if (len(data) % 4) != 0 else ''
    return base64.urlsafe_b64decode(data + padding)

class SecureJWTHandler:
    """
    Cryptographic JWT Generator & Validator enforcing HS256 HMAC signature checks,
    expiration verification, and strict algorithm lockdown.
    """

    def __init__(self, secret_key: str, issuer: str = "pysecutils-auth", audience: str = "pysecutils-api"):
        if not secret_key or len(secret_key) < 16:
            raise ValueError("Secret key must be at least 16 characters long.")
        self.secret_key = secret_key.encode('utf-8')
        self.issuer = issuer
        self.audience = audience

    def create_token(self, subject: str, custom_claims: Dict[str, Any] = None, expires_in_seconds: int = 3600) -> str:
        now = int(time.time())
        header = {"typ": "JWT", "alg": "HS256"}
        payload = {
            "sub": subject,
            "iss": self.issuer,
            "aud": self.audience,
            "iat": now,
            "nbf": now,
            "exp": now + expires_in_seconds,
        }
        if custom_claims:
            payload.update(custom_claims)

        header_b64 = _b64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_b64 = _b64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        
        signature = hmac.new(self.secret_key, signing_input, hashlib.sha256).digest()
        sig_b64 = _b64url_encode(signature)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def verify_token(self, token: str) -> Dict[str, Any]:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Malformed JWT token structure.")

        header_b64, payload_b64, sig_b64 = parts
        
        # Verify header algorithm
        try:
            header = json.loads(_b64url_decode(header_b64).decode('utf-8'))
        except Exception:
            raise ValueError("Invalid JWT header encoding.")
            
        if header.get("alg") != "HS256":
            raise ValueError(f"Unauthorized or insecure JWT algorithm: {header.get('alg')}")

        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        expected_sig = hmac.new(self.secret_key, signing_input, hashlib.sha256).digest()
        actual_sig = _b64url_decode(sig_b64)

        if not hmac.compare_digest(actual_sig, expected_sig):
            raise ValueError("Invalid JWT signature.")

        # Verify claims
        try:
            payload = json.loads(_b64url_decode(payload_b64).decode('utf-8'))
        except Exception:
            raise ValueError("Invalid JWT payload encoding.")

        now = int(time.time())
        if "exp" in payload and now > payload["exp"]:
            raise ValueError("Token has expired.")
        if "nbf" in payload and now < payload["nbf"]:
            raise ValueError("Token is not active yet.")
        if "iss" in payload and payload["iss"] != self.issuer:
            raise ValueError("Invalid token issuer.")
        if "aud" in payload and payload["aud"] != self.audience:
            raise ValueError("Invalid token audience.")

        return payload
