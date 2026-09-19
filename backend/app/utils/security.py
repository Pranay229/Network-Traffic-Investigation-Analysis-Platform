"""
Security Utilities:
- Argon2id password hashing & verification
- Strong password policy enforcement
- JWT access token signing & validation
- Secure random token generation & SHA-256 hashing
- CSRF double-submit helpers
- Safe redirect URL validation
"""
import re
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Optional, List, Tuple
from urllib.parse import urlparse
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from app.config import settings

# Initialize Argon2id password hasher with secure parameters
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

# Common weak passwords blacklist (checked in addition to complexity rules)
COMMON_WEAK_PASSWORDS = {
    "password1234", "password12345", "password123456", "admin12345678",
    "administrator1", "qwertyuiop123", "letmein123456", "welcome123456",
    "123456789012", "changeme12345", "iloveyou12345", "monkey1234567",
    "dragon1234567", "master1234567", "football12345", "sunshine12345",
}


def hash_password(password: str) -> str:
    """Hash plaintext password using Argon2id."""
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against Argon2id hash. Returns True if valid, False otherwise."""
    try:
        return ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        return False


def validate_password_strength(password: str, user_inputs: Optional[List[str]] = None) -> Tuple[bool, Optional[str]]:
    """
    Enforce strong password policy:
    - Minimum 12 characters (max 128)
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    - Not containing common weak passwords
    - Does not contain user's name or email handle
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if len(password) > 128:
        return False, "Password must not exceed 128 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_+=\[\]\\/`~]", password):
        return False, "Password must contain at least one special character."
    
    pwd_lower = password.lower()
    for weak in COMMON_WEAK_PASSWORDS:
        if weak in pwd_lower:
            return False, "Password contains a commonly used or compromised pattern."
    
    if user_inputs:
        for val in user_inputs:
            if val and len(val.strip()) >= 3:
                clean_val = val.strip().lower()
                if "@" in clean_val:
                    clean_val = clean_val.split("@")[0]
                if clean_val in pwd_lower:
                    return False, "Password must not contain parts of your name or email handle."

    return True, None


def normalize_email(email: str) -> str:
    """Normalize email address to lowercase and strip whitespace."""
    return email.strip().lower()


def validate_email_format(email: str) -> bool:
    """Validate email format with regex."""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email.strip()))


def create_access_token(
    data: Optional[dict] = None,
    expires_delta: Optional[timedelta] = None,
    user_id: Optional[int] = None,
    email: Optional[str] = None,
    role: Optional[str] = None,
    session_id: Optional[str] = None
) -> str:
    """Create a short-lived signed JWT access token."""
    to_encode = {}
    if data:
        to_encode.update(data)
    else:
        if user_id: to_encode["sub"] = str(user_id)
        if email: to_encode["email"] = email
        if role: to_encode["role"] = role
        if session_id: to_encode["session_id"] = session_id

    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
    to_encode.update({
        "type": "access",
        "exp": expire,
        "iat": now
    })
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[dict[str, Any]]:
    """Decode and validate JWT access token. Returns payload dict or None if invalid/expired."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "access":
            return None
        return payload
    except jwt.PyJWTError:
        return None


def generate_secure_random_token(length_bytes: int = 32) -> str:
    """Generate a cryptographically secure random hex token."""
    return secrets.token_hex(length_bytes)


def generate_secure_token() -> Tuple[str, str]:
    """Generate raw hex token and its SHA-256 hash."""
    raw = generate_secure_random_token(32)
    return raw, hash_token_sha256(raw)


def hash_token_sha256(token: str) -> str:
    """Hash a token using SHA-256 for secure database storage/lookup."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_token(token: str) -> str:
    """Alias for hash_token_sha256."""
    return hash_token_sha256(token)


def generate_csrf_token() -> str:
    """Generate a random CSRF token for double-submit cookie validation."""
    return secrets.token_urlsafe(32)


def is_safe_redirect_url(url: str, allowed_hosts: Optional[set] = None) -> bool:
    """Prevent Open Redirect attacks by validating redirect targets."""
    if not url:
        return False
    parsed = urlparse(url)
    if not parsed.netloc:
        # Relative path
        return url.startswith("/") and not url.startswith("//")
    
    if allowed_hosts and parsed.netloc in allowed_hosts:
        return True
    return False
