from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64

def hash_password(password: str) -> tuple:
    # Generate random salt
    salt = os.urandom(16)

    # Derive secure key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    key = kdf.derive(password.encode())
    return base64.b64encode(salt), base64.b64encode(key)

def verify_password(password: str, salt_b64: bytes, key_b64: bytes) -> bool:
    # Verify password against stored hash
    salt = base64.b64decode(salt_b64)
    stored_key = base64.b64decode(key_b64)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    try:
        kdf.verify(password.encode(), stored_key)
        return True
    except Exception:
        return False
