import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from app.core.config import settings

def _get_fernet_instance() -> Fernet:
    """
    Derives a 256-bit key from settings.SECRET_KEY using SHA-256,
    and returns a Fernet authenticated encryption instance (AES-128-CBC + HMAC-SHA256).
    """
    master_secret = settings.SECRET_KEY.encode("utf-8")
    derived_key = hashlib.sha256(master_secret).digest()
    fernet_key = base64.urlsafe_b64encode(derived_key)
    return Fernet(fernet_key)

def encrypt_api_key(plaintext_key: str) -> str:
    """
    Encrypts an API key using industry-standard Fernet authenticated encryption (AEAD).
    Generates a fresh 128-bit random IV and HMAC-SHA256 signature for tamper protection.
    """
    if not plaintext_key:
        return ""
    fernet = _get_fernet_instance()
    token_bytes = fernet.encrypt(plaintext_key.encode("utf-8"))
    return token_bytes.decode("utf-8")

def decrypt_api_key(encrypted_key: str) -> str:
    """
    Decrypts an API key after verifying HMAC-SHA256 signature integrity.
    Strictly uses Fernet AEAD. Invalid or tampered tokens return an empty string.
    """
    if not encrypted_key:
        return ""
    try:
        fernet = _get_fernet_instance()
        decrypted_bytes = fernet.decrypt(encrypted_key.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except (InvalidToken, Exception):
        return ""

def mask_api_key(plaintext_key: str) -> str:
    """
    Masks plaintext API key for safe public rendering (e.g. sk-p••••••••4f2a).
    """
    if not plaintext_key or len(plaintext_key) < 8:
        return "••••••••"
    return f"{plaintext_key[:4]}••••••••{plaintext_key[-4:]}"
