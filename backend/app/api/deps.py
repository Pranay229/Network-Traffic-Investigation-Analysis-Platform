"""
Authentication, Authorization, Rate Limiting, and Request Metadata Dependencies.
"""
import time
from datetime import datetime, timezone
from collections import defaultdict
from typing import Callable, Optional, Union
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.database.base import get_db
from app.models.user import User, UserSession
from app.models.investigation import Investigation
from app.utils.security import decode_access_token, hash_token_sha256

# Bearer token extractor (auto_error=False to allow custom 401 handling)
security = HTTPBearer(auto_error=False)


# ─── Request Metadata Helpers ────────────────────────────────────────────────

def get_client_ip(request: Request) -> str:
    """Extract real client IP address, checking X-Forwarded-For if behind a proxy."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def get_user_agent(request: Request) -> str:
    """Extract client User-Agent string."""
    return request.headers.get("User-Agent", "Unknown Browser")[:500]


# ─── In-Memory Rate Limiter ──────────────────────────────────────────────────

class InMemoryRateLimiter:
    """Simple in-memory sliding window rate limiter per key."""
    def __init__(self):
        self.requests: dict[str, list[float]] = defaultdict(list)

    def check_rate_limit(self, key: str, max_requests: int, window_seconds: int) -> bool:
        now = time.time()
        self.requests[key] = [t for t in self.requests[key] if now - t < window_seconds]
        if len(self.requests[key]) >= max_requests:
            return False
        self.requests[key].append(now)
        return True


rate_limiter = InMemoryRateLimiter()


def enforce_rate_limit(key_prefix: str, max_requests: int, window_seconds: int):
    """Dependency factory for endpoint rate limiting."""
    def dependency(request: Request):
        ip = get_client_ip(request)
        key = f"{key_prefix}:{ip}"
        if not rate_limiter.check_rate_limit(key, max_requests, window_seconds):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please slow down and try again later."
            )
    return dependency


rate_limit_login = enforce_rate_limit("login", 15, 60)
rate_limit_auth_actions = enforce_rate_limit("auth", 20, 60)


# ─── Open Access / Authentication Dependencies ──────────────────────────────

def _get_or_create_default_user(db: Session) -> User:
    """Retrieve an existing user or create a default active SOC Analyst."""
    user = db.query(User).filter(User.role == "ADMIN").first()
    if not user:
        user = db.query(User).first()
    if not user:
        user = User(
            email="analyst@novacyberspark.local",
            full_name="SOC Analyst",
            password_hash="argon2id$open_mode_no_login",
            role="ADMIN",
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
    db: Session = Depends(get_db),
) -> User:
    """Return active user (open access: defaults to system SOC Analyst if no token)."""
    if credentials and credentials.credentials:
        token = credentials.credentials
        payload = decode_access_token(token)
        if payload and payload.get("sub"):
            try:
                user_id_int = int(payload.get("sub"))
                user = db.query(User).filter(User.id == user_id_int).first()
                if user:
                    return user
            except (ValueError, TypeError):
                pass

    return _get_or_create_default_user(db)


def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Returns active user in open access mode."""
    return current_user


def get_current_active_verified_user(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """Returns verified user in open access mode."""
    return current_user


# ─── RBAC Role Dependencies (Open Access) ────────────────────────────────────

def require_role(allowed_roles: list[str]) -> Callable:
    """Enforces RBAC: verifies current user has one of the allowed roles."""
    def role_checker(user: User = Depends(get_current_active_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Insufficient privileges. Required role in {allowed_roles}, but found '{user.role}'."
            )
        return user
    return role_checker


require_admin = require_role(["ADMIN"])
require_analyst_or_admin = require_role(["ADMIN", "ANALYST"])
require_any_authenticated = require_role(["ADMIN", "ANALYST", "VIEWER"])


# ─── Investigation Access (Open Access) ──────────────────────────────────────

def _try_int(v: str) -> int:
    try:
        return int(v)
    except Exception:
        return -1


def check_investigation_access(
    inv_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Investigation:
    """Resolves investigation and enforces RBAC & IDOR protection."""
    inv = db.query(Investigation).filter(
        (Investigation.inv_id == inv_id) | (Investigation.id == _try_int(inv_id))
    ).first()

    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found.")

    # RBAC & IDOR Enforcement:
    # ADMIN has full visibility.
    # If investigation has an assigned owner, VIEWER role cannot access other users' private cases.
    if current_user.role == "ADMIN":
        return inv

    if inv.user_id is not None and inv.user_id != current_user.id:
        if current_user.role == "VIEWER":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. Viewers can only access authorized investigations."
            )

    return inv


def check_investigation_deletion_access(
    inv_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Investigation:
    """Checks deletion permissions: Viewers are forbidden; Analysts can delete own cases; Admins can delete any."""
    inv = db.query(Investigation).filter(
        (Investigation.inv_id == inv_id) | (Investigation.id == _try_int(inv_id))
    ).first()

    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found.")

    if current_user.role == "VIEWER":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Viewers do not have permission to delete investigations."
        )

    if current_user.role == "ANALYST":
        if inv.user_id is not None and inv.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Analysts cannot delete investigations owned by other users."
            )

    return inv


def revoke_user_session(db: Session, session_id: int, user_id: int) -> bool:
    """Revoke a specific database session record."""
    session_rec = db.query(UserSession).filter(
        UserSession.id == session_id,
        UserSession.user_id == user_id,
        UserSession.revoked_at.is_(None)
    ).first()
    if session_rec:
        session_rec.revoked_at = datetime.now(timezone.utc)
        db.commit()
        return True
    return False
