import os
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class AESGCMCipher:
    """Authenticated AES-256-GCM encryption and decryption."""
    
    def __init__(self, key: bytes = None):
        if key is None:
            self.key = AESGCM.generate_key(bit_length=256)
        else:
            if len(key) != 32:
                raise ValueError("AES-256 key must be exactly 32 bytes.")
            self.key = key
        self._aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext

    def decrypt(self, nonce_and_ciphertext: bytes, associated_data: bytes = None) -> bytes:
        if len(nonce_and_ciphertext) < 28:
            raise ValueError("Ciphertext too short.")
        nonce = nonce_and_ciphertext[:12]
        ciphertext = nonce_and_ciphertext[12:]
        return self._aesgcm.decrypt(nonce, ciphertext, associated_data)

    def encrypt_to_base64(self, plaintext: str, associated_data: str = None) -> str:
        pt_bytes = plaintext.encode('utf-8')
        ad_bytes = associated_data.encode('utf-8') if associated_data else None
        encrypted = self.encrypt(pt_bytes, ad_bytes)
        return base64.b64encode(encrypted).decode('ascii')

    def decrypt_from_base64(self, b64_ciphertext: str, associated_data: str = None) -> str:
        encrypted = base64.b64decode(b64_ciphertext.encode('ascii'))
        ad_bytes = associated_data.encode('utf-8') if associated_data else None
        decrypted = self.decrypt(encrypted, ad_bytes)
        return decrypted.decode('utf-8')

def derive_key(secret: str, salt: bytes, length: int = 32, iterations: int = 100_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(secret.encode('utf-8'))

def hash_password(password: str, salt: bytes = None, iterations: int = 100_000) -> str:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    salt_b64 = base64.b64encode(salt).decode('ascii')
    dk_b64 = base64.b64encode(dk).decode('ascii')
    return f"pbkdf2_sha256${iterations}${salt_b64}${dk_b64}"

def verify_password(password: str, hashed_str: str) -> bool:
    try:
        scheme, iterations_str, salt_b64, dk_b64 = hashed_str.split('$')
        if scheme != 'pbkdf2_sha256':
            return False
        iterations = int(iterations_str)
        salt = base64.b64decode(salt_b64.encode('ascii'))
        expected_dk = base64.b64decode(dk_b64.encode('ascii'))
        actual_dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        return hmac.compare_digest(actual_dk, expected_dk)
    except Exception:
        return False
