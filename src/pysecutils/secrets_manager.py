import secrets
import string
import hmac

def generate_secure_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)

def generate_api_key(prefix: str = "pk_live", length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(alphabet) for _ in range(length))
    return f"{prefix}_{token}"

def constant_time_compare(val1: str, val2: str) -> bool:
    return hmac.compare_digest(val1.encode('utf-8'), val2.encode('utf-8'))
