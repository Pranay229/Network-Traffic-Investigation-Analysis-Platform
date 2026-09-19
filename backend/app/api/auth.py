import re
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, BackgroundTasks
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session

from app.config import settings
from app.database.base import get_db
from app.models.user import User, UserSession, EmailVerificationToken, PasswordResetToken
from app.models.audit import AuditLog
from app.utils.security import (
    hash_password,
    verify_password,
    validate_password_strength,
    create_access_token,
    generate_secure_random_token,
    hash_token_sha256,
    generate_csrf_token,
    is_safe_redirect_url
)
from app.services.email_service import email_service
from app.services.audit_service import audit_service
from app.api.deps import (
    get_current_user,
    get_current_active_user,
    get_client_ip,
    get_user_agent,
    rate_limit_login,
    rate_limit_auth_actions,
    revoke_user_session
)

router = APIRouter(prefix="/auth", tags=["Authentication & Sessions"])


# ==========================================
# PYDANTIC SCHEMAS
# ==========================================

class RegisterRequest(BaseModel):
    full_name: str
    email: str
    password: str
    confirm_password: str

    @field_validator("full_name")
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2 or len(v) > 100:
            raise ValueError("Full name must be between 2 and 100 characters.")
        return v

    @field_validator("email")
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or len(v) < 5 or "." not in v:
            raise ValueError("Invalid email format.")
        return v

    @field_validator("confirm_password")
    def passwords_match(cls, v: str, info) -> str:
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match.")
        return v


class LoginRequest(BaseModel):
    email: str
    password: str
    remember_me: bool = False

    @field_validator("email")
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or len(v) < 5:
            raise ValueError("Invalid email format.")
        return v


class ForgotPasswordRequest(BaseModel):
    email: str

    @field_validator("email")
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or len(v) < 5:
            raise ValueError("Invalid email format.")
        return v


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
    confirm_password: str

    @field_validator("confirm_password")
    def passwords_match(cls, v: str, info) -> str:
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match.")
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str

    @field_validator("confirm_password")
    def passwords_match(cls, v: str, info) -> str:
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match.")
        return v


class UpdateProfileRequest(BaseModel):
    full_name: str

    @field_validator("full_name")
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2 or len(v) > 100:
            raise ValueError("Full name must be between 2 and 100 characters.")
        return v


class ResendVerificationRequest(BaseModel):
    email: str

    @field_validator("email")
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or len(v) < 5:
            raise ValueError("Invalid email format.")
        return v


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    is_email_verified: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AuthResponse(BaseModel):
    user: UserResponse
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    csrf_token: str


class SessionResponse(BaseModel):
    id: int
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: datetime
    last_used_at: datetime
    is_current: bool

    class Config:
        from_attributes = True


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _set_auth_cookies(response: Response, raw_refresh_token: str, csrf_token: str, max_age_days: int):
    max_age_seconds = max_age_days * 24 * 60 * 60
    
    # Set HttpOnly refresh token cookie
    response.set_cookie(
        key="refresh_token",
        value=raw_refresh_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE.lower(),
        max_age=max_age_seconds,
        path="/api/auth"  # Restrict scope to auth endpoints
    )
    
    # Set double-submit CSRF cookie (accessible to client JS to mirror in X-CSRF-Token header)
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE.lower(),
        max_age=max_age_seconds,
        path="/"
    )


def _clear_auth_cookies(response: Response):
    response.delete_cookie(key="refresh_token", path="/api/auth")
    response.delete_cookie(key="csrf_token", path="/")


# ==========================================
# ENDPOINTS
# ==========================================

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
    _limiter = Depends(rate_limit_auth_actions)
):
    """
    Registers a new user account with secure Argon2id password hashing,
    email verification token generation, and audit logging.
    """
    email_clean = payload.email.lower().strip()
    
    # 1. Enforce strong password validation
    is_strong, msg = validate_password_strength(payload.password, user_inputs=[payload.full_name, email_clean])
    if not is_strong:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    
    # 2. Check if user already exists
    existing = db.query(User).filter(User.email == email_clean).first()
    if existing:
        # Prevent user enumeration with generic registration response or standard error
        # To avoid confusion while protecting security:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists. Please log in or reset your password."
        )
    
    # 3. Check if this is the very first user in the system (auto-promote to ADMIN for setup convenience if configured, otherwise ANALYST)
    user_count = db.query(User).count()
    initial_role = "ADMIN" if user_count == 0 else "ANALYST"
    
    # 4. Hash password with Argon2id
    pwd_hash = hash_password(payload.password)
    
    # 5. Create user record
    new_user = User(
        email=email_clean,
        hashed_password=pwd_hash,
        full_name=payload.full_name,
        role=initial_role,
        is_active=True,
        is_email_verified=False
    )
    db.add(new_user)
    db.flush()  # populate ID
    
    # 6. Generate single-use email verification token
    raw_token = generate_secure_random_token(48)
    token_hash = hash_token_sha256(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
    
    verify_record = EmailVerificationToken(
        user_id=new_user.id,
        token_hash=token_hash,
        expires_at=expires_at
    )
    db.add(verify_record)
    
    # 7. Audit log registration
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    audit_service.log_event(
        db=db,
        event_type="AUTH_REGISTER",
        user_id=new_user.id,
        ip_address=client_ip,
        user_agent=user_agent,
        resource_type="User",
        resource_id=str(new_user.id),
        metadata={"role": initial_role, "email": email_clean}
    )
    
    db.commit()
    
    # 8. Send verification email (or log to dev console)
    background_tasks.add_task(
        email_service.send_verification_email,
        email_clean,
        new_user.full_name,
        raw_token
    )
    
    return {
        "message": "Registration successful. Please check your email to verify your account.",
        "email": email_clean,
        "requires_verification": True
    }


@router.get("/verify-email")
def verify_email(
    token: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Verifies user email using the single-use token.
    """
    if not token or len(token) < 20:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification token.")
    
    token_hash = hash_token_sha256(token)
    now = datetime.now(timezone.utc)
    
    record = db.query(EmailVerificationToken).filter(
        EmailVerificationToken.token_hash == token_hash,
        EmailVerificationToken.used_at.is_(None)
    ).first()
    
    if not record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification token is invalid or has already been used."
        )
    
    record_expires = record.expires_at
    if record_expires.tzinfo is None:
        record_expires = record_expires.replace(tzinfo=timezone.utc)
    
    if record_expires < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification token has expired. Please request a new verification email."
        )
    
    # Mark token used
    record.used_at = now
    
    # Mark user email verified
    user = db.query(User).filter(User.id == record.user_id).first()
    if user:
        user.is_email_verified = True
        
        # Audit log
        client_ip = get_client_ip(request)
        user_agent = get_user_agent(request)
        audit_service.log_event(
            db=db,
            event_type="AUTH_EMAIL_VERIFIED",
            user_id=user.id,
            ip_address=client_ip,
            user_agent=user_agent,
            resource_type="User",
            resource_id=str(user.id),
            metadata={"email": user.email}
        )
    
    db.commit()
    return {"message": "Email verified successfully. You may now log in to the platform."}


@router.post("/resend-verification")
def resend_verification(
    payload: ResendVerificationRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
    _limiter = Depends(rate_limit_auth_actions)
):
    """
    Resends verification email. Uses generic response to avoid email enumeration.
    """
    email_clean = payload.email.lower().strip()
    user = db.query(User).filter(User.email == email_clean).first()
    
    if user and not user.is_email_verified:
        # Invalidate old unused tokens
        db.query(EmailVerificationToken).filter(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.used_at.is_(None)
        ).update({"used_at": datetime.now(timezone.utc)})
        
        # Generate new token
        raw_token = generate_secure_random_token(48)
        token_hash = hash_token_sha256(raw_token)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        
        verify_record = EmailVerificationToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at
        )
        db.add(verify_record)
        db.commit()
        
        background_tasks.add_task(
            email_service.send_verification_email,
            user.email,
            user.full_name,
            raw_token
        )
    
    return {"message": "If an unverified account with this email exists, a verification link has been sent."}


@router.post("/login", response_model=AuthResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _limiter = Depends(rate_limit_login)
):
    """
    Authenticates user, verifies password with Argon2id, checks account lockout,
    creates a database-backed session, sets HttpOnly cookies, and returns JWT access token.
    """
    email_clean = payload.email.lower().strip()
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    now = datetime.now(timezone.utc)
    
    generic_auth_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password."
    )
    
    user = db.query(User).filter(User.email == email_clean).first()
    
    if not user:
        # Run dummy Argon2id hash to mitigate timing attacks against non-existent users
        verify_password("dummy_password_timing_defense", "$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy")
        audit_service.log_event(
            db=db,
            event_type="AUTH_LOGIN_FAILURE",
            ip_address=client_ip,
            user_agent=user_agent,
            metadata={"attempted_email": email_clean, "reason": "User not found"}
        )
        db.commit()
        raise generic_auth_error
    
    # Check if account is active
    if not user.is_active:
        audit_service.log_event(
            db=db,
            event_type="AUTH_LOGIN_LOCKED",
            user_id=user.id,
            ip_address=client_ip,
            user_agent=user_agent,
            metadata={"reason": "Account deactivated"}
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been deactivated. Please contact your SOC administrator."
        )
    
    # Check account lockout
    if user.locked_until:
        lock_expiry = user.locked_until
        if lock_expiry.tzinfo is None:
            lock_expiry = lock_expiry.replace(tzinfo=timezone.utc)
        
        if lock_expiry > now:
            remaining_mins = int((lock_expiry - now).total_seconds() / 60) + 1
            audit_service.log_event(
                db=db,
                event_type="AUTH_LOGIN_LOCKED",
                user_id=user.id,
                ip_address=client_ip,
                user_agent=user_agent,
                metadata={"locked_until": lock_expiry.isoformat()}
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Account temporarily locked due to excessive failed attempts. Please try again in {remaining_mins} minutes."
            )
        else:
            # Lockout expired, reset counter
            user.failed_login_attempts = 0
            user.locked_until = None
    
    # Verify password
    if not verify_password(payload.password, user.hashed_password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
            audit_service.log_event(
                db=db,
                event_type="AUTH_ACCOUNT_LOCKED",
                user_id=user.id,
                ip_address=client_ip,
                user_agent=user_agent,
                metadata={"failed_attempts": user.failed_login_attempts}
            )
            
            # Send security alert email
            background_tasks.add_task(
                email_service.send_security_alert,
                user.email,
                user.full_name,
                "Account Locked: Multiple Failed Login Attempts",
                f"Your account was temporarily locked for {settings.LOCKOUT_DURATION_MINUTES} minutes following {user.failed_login_attempts} failed login attempts from IP {client_ip}."
            )
        else:
            audit_service.log_event(
                db=db,
                event_type="AUTH_LOGIN_FAILURE",
                user_id=user.id,
                ip_address=client_ip,
                user_agent=user_agent,
                metadata={"failed_attempts": user.failed_login_attempts}
            )
        
        db.commit()
        raise generic_auth_error
    
    # Optional check: require email verification before allowing login in production
    # In development, we can allow login with unverified email or warn
    # (Unverified users can still log in if permitted, but have unverified badge)
    
    # Successful login: reset failed attempts & update last login
    is_new_ip_or_agent = (user.last_login_ip and user.last_login_ip != client_ip)
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    user.last_login_ip = client_ip
    
    # 1. Create short-lived access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "email": user.email,
            "role": user.role,
            "name": user.full_name
        },
        expires_delta=access_token_expires
    )
    
    # 2. Create rotating refresh token and database session
    raw_refresh_token = generate_secure_random_token(64)
    token_hash = hash_token_sha256(raw_refresh_token)
    
    refresh_days = settings.REFRESH_TOKEN_EXPIRE_DAYS if payload.remember_me else 1
    session_expires_at = now + timedelta(days=refresh_days)
    
    user_session = UserSession(
        user_id=user.id,
        session_id=secrets.token_hex(16),
        token_hash=token_hash,
        ip_address=client_ip,
        user_agent=user_agent,
        expires_at=session_expires_at,
        last_used_at=now
    )
    db.add(user_session)
    
    # 3. Generate CSRF token
    csrf_token = generate_csrf_token()
    
    # 4. Set HttpOnly and CSRF cookies
    _set_auth_cookies(response, raw_refresh_token, csrf_token, max_age_days=refresh_days)
    
    # 5. Audit log successful login
    audit_service.log_event(
        db=db,
        event_type="AUTH_LOGIN_SUCCESS",
        user_id=user.id,
        ip_address=client_ip,
        user_agent=user_agent,
        resource_type="UserSession",
        resource_id=str(user_session.id if user_session.id else "new"),
        metadata={"role": user.role}
    )
    
    db.commit()
    
    # Send new login alert email if different IP
    if is_new_ip_or_agent:
        background_tasks.add_task(
            email_service.send_security_alert,
            user.email,
            user.full_name,
            "Security Alert: New Sign-In Detected",
            f"A new sign-in was detected for your account from IP {client_ip} ({user_agent[:60]}...) on {now.strftime('%Y-%m-%d %H:%M:%S UTC')}."
        )
    
    return AuthResponse(
        user=UserResponse.model_validate(user),
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        csrf_token=csrf_token
    )


@router.post("/refresh", response_model=AuthResponse)
def refresh_token(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Validates HttpOnly refresh cookie, verifies database session, rotates refresh token,
    and returns a fresh JWT access token with new CSRF token.
    """
    raw_refresh_token = request.cookies.get("refresh_token")
    if not raw_refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token cookie missing. Please log in."
        )
    
    token_hash = hash_token_sha256(raw_refresh_token)
    now = datetime.now(timezone.utc)
    
    # Lookup active session
    user_session = db.query(UserSession).filter(
        UserSession.token_hash == token_hash,
        UserSession.revoked_at.is_(None)
    ).first()
    
    if not user_session:
        _clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or was revoked. Please sign in again."
        )
    
    session_expiry = user_session.expires_at
    if session_expiry.tzinfo is None:
        session_expiry = session_expiry.replace(tzinfo=timezone.utc)
    
    if session_expiry < now:
        user_session.revoked_at = now
        db.commit()
        _clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired. Please sign in again."
        )
    
    # Lookup user
    user = db.query(User).filter(User.id == user_session.user_id).first()
    if not user or not user.is_active:
        user_session.revoked_at = now
        db.commit()
        _clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or disabled."
        )
    
    # Token Rotation: Generate new refresh token and update DB session
    new_raw_refresh_token = generate_secure_random_token(64)
    new_token_hash = hash_token_sha256(new_raw_refresh_token)
    
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    user_session.token_hash = new_token_hash
    user_session.last_used_at = now
    user_session.ip_address = client_ip
    user_session.user_agent = user_agent
    
    # Create new access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "email": user.email,
            "role": user.role,
            "name": user.full_name
        },
        expires_delta=access_token_expires
    )
    
    # Generate new CSRF token
    csrf_token = generate_csrf_token()
    
    # Set updated cookies
    _set_auth_cookies(response, new_raw_refresh_token, csrf_token, max_age_days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    db.commit()
    
    return AuthResponse(
        user=UserResponse.model_validate(user),
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        csrf_token=csrf_token
    )


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Invalidates current session, revokes refresh token in database, clears auth cookies.
    """
    raw_refresh_token = request.cookies.get("refresh_token")
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    now = datetime.now(timezone.utc)
    
    if raw_refresh_token:
        token_hash = hash_token_sha256(raw_refresh_token)
        session_rec = db.query(UserSession).filter(UserSession.token_hash == token_hash).first()
        if session_rec:
            session_rec.revoked_at = now
    
    # Clear cookies
    _clear_auth_cookies(response)
    
    audit_service.log_event(
        db=db,
        event_type="AUTH_LOGOUT",
        user_id=current_user.id,
        ip_address=client_ip,
        user_agent=user_agent
    )
    
    db.commit()
    return {"message": "Logged out successfully."}


@router.post("/logout-all")
def logout_all_devices(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Revokes ALL active sessions for the user across all devices.
    """
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    now = datetime.now(timezone.utc)
    
    # Revoke all active sessions
    db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.revoked_at.is_(None)
    ).update({"revoked_at": now})
    
    # Clear local cookies
    _clear_auth_cookies(response)
    
    audit_service.log_event(
        db=db,
        event_type="AUTH_LOGOUT_ALL_DEVICES",
        user_id=current_user.id,
        ip_address=client_ip,
        user_agent=user_agent
    )
    
    db.commit()
    return {"message": "All sessions have been revoked. Please sign in again."}


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_active_user)):
    """
    Returns the currently authenticated user's profile.
    """
    return UserResponse.model_validate(current_user)


@router.put("/profile", response_model=UserResponse)
def update_profile(
    payload: UpdateProfileRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Updates the authenticated user's profile info (e.g. full name).
    """
    old_name = current_user.full_name
    current_user.full_name = payload.full_name
    
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    audit_service.log_event(
        db=db,
        event_type="USER_PROFILE_UPDATED",
        user_id=current_user.id,
        ip_address=client_ip,
        user_agent=user_agent,
        metadata={"old_name": old_name, "new_name": payload.full_name}
    )
    
    db.commit()
    return UserResponse.model_validate(current_user)


@router.post("/change-password")
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    _limiter = Depends(rate_limit_auth_actions)
):
    """
    Allows authenticated users to change their password.
    Requires current password verification and enforces password complexity.
    Revokes all other sessions.
    """
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    now = datetime.now(timezone.utc)
    
    # 1. Verify current password
    if not verify_password(payload.current_password, current_user.hashed_password):
        audit_service.log_event(
            db=db,
            event_type="AUTH_PASSWORD_CHANGE_FAILURE",
            user_id=current_user.id,
            ip_address=client_ip,
            user_agent=user_agent,
            metadata={"reason": "Incorrect current password"}
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect."
        )
    
    # 2. Enforce new password strength
    is_strong, msg = validate_password_strength(payload.new_password, user_inputs=[current_user.full_name, current_user.email])
    if not is_strong:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    
    # 3. Hash new password with Argon2id
    new_hash = hash_password(payload.new_password)
    current_user.hashed_password = new_hash
    
    # 4. Revoke other sessions (keep current session)
    raw_refresh_token = request.cookies.get("refresh_token")
    current_token_hash = hash_token_sha256(raw_refresh_token) if raw_refresh_token else None
    
    query = db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.revoked_at.is_(None)
    )
    if current_token_hash:
        query = query.filter(UserSession.token_hash != current_token_hash)
    
    query.update({"revoked_at": now})
    
    # 5. Audit log
    audit_service.log_event(
        db=db,
        event_type="AUTH_PASSWORD_CHANGED",
        user_id=current_user.id,
        ip_address=client_ip,
        user_agent=user_agent
    )
    
    db.commit()
    
    # 6. Send notification email
    background_tasks.add_task(
        email_service.send_security_alert,
        current_user.email,
        current_user.full_name,
        "Security Alert: Password Changed",
        f"The password for your account was changed on {now.strftime('%Y-%m-%d %H:%M:%S UTC')} from IP {client_ip}. If you did not make this change, please contact your SOC administrator immediately."
    )
    
    return {"message": "Password changed successfully. Other active sessions have been revoked."}


@router.post("/forgot-password")
def forgot_password(
    payload: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
    _limiter = Depends(rate_limit_auth_actions)
):
    """
    Generates a secure, single-use password reset token and emails it to the user.
    Always returns a generic message to prevent account enumeration.
    """
    email_clean = payload.email.lower().strip()
    user = db.query(User).filter(User.email == email_clean).first()
    
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    now = datetime.now(timezone.utc)
    
    if user and user.is_active:
        # Invalidate old unused reset tokens
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None)
        ).update({"used_at": now})
        
        # Generate new reset token (expires in 1 hour)
        raw_token = generate_secure_random_token(48)
        token_hash = hash_token_sha256(raw_token)
        expires_at = now + timedelta(hours=1)
        
        reset_record = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at
        )
        db.add(reset_record)
        
        audit_service.log_event(
            db=db,
            event_type="AUTH_PASSWORD_RESET_REQUESTED",
            user_id=user.id,
            ip_address=client_ip,
            user_agent=user_agent,
            metadata={"email": email_clean}
        )
        
        db.commit()
        
        # Send reset email
        background_tasks.add_task(
            email_service.send_password_reset_email,
            user.email,
            user.full_name,
            raw_token
        )
    else:
        audit_service.log_event(
            db=db,
            event_type="AUTH_PASSWORD_RESET_ATTEMPT_UNKNOWN",
            ip_address=client_ip,
            user_agent=user_agent,
            metadata={"attempted_email": email_clean}
        )
        db.commit()
    
    return {"message": "If an active account exists for this email address, password reset instructions have been sent."}


@router.post("/reset-password")
def reset_password(
    payload: ResetPasswordRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    _limiter = Depends(rate_limit_auth_actions)
):
    """
    Resets user password using the single-use reset token.
    Validates token expiration, hashes new password with Argon2id,
    and invalidates all existing sessions.
    """
    if not payload.token or len(payload.token) < 20:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid password reset token.")
    
    token_hash = hash_token_sha256(payload.token)
    now = datetime.now(timezone.utc)
    
    record = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == token_hash,
        PasswordResetToken.used_at.is_(None)
    ).first()
    
    if not record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset token is invalid or has already been used."
        )
    
    record_expires = record.expires_at
    if record_expires.tzinfo is None:
        record_expires = record_expires.replace(tzinfo=timezone.utc)
    
    if record_expires < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset token has expired. Please request a new password reset."
        )
    
    user = db.query(User).filter(User.id == record.user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User account not found.")
    
    # Validate password strength
    is_strong, msg = validate_password_strength(payload.new_password, user_inputs=[user.full_name, user.email])
    if not is_strong:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    
    # Hash new password
    user.hashed_password = hash_password(payload.new_password)
    user.failed_login_attempts = 0
    user.locked_until = None
    
    # Mark reset token as used
    record.used_at = now
    
    # Invalidate ALL active sessions across all devices
    db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.revoked_at.is_(None)
    ).update({"revoked_at": now})
    
    _clear_auth_cookies(response)
    
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    audit_service.log_event(
        db=db,
        event_type="AUTH_PASSWORD_RESET_SUCCESS",
        user_id=user.id,
        ip_address=client_ip,
        user_agent=user_agent
    )
    
    db.commit()
    
    background_tasks.add_task(
        email_service.send_security_alert,
        user.email,
        user.full_name,
        "Security Alert: Password Reset Successful",
        f"Your account password was successfully reset on {now.strftime('%Y-%m-%d %H:%M:%S UTC')} from IP {client_ip}. You can now sign in with your new password."
    )
    
    return {"message": "Your password has been reset. Please sign in again."}


@router.get("/sessions", response_model=List[SessionResponse])
def get_user_sessions(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lists all active sessions for the current user.
    """
    raw_refresh_token = request.cookies.get("refresh_token")
    current_token_hash = hash_token_sha256(raw_refresh_token) if raw_refresh_token else None
    
    sessions = db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.revoked_at.is_(None)
    ).order_by(UserSession.last_used_at.desc()).all()
    
    result = []
    for s in sessions:
        result.append(SessionResponse(
            id=s.id,
            ip_address=s.ip_address,
            user_agent=s.user_agent,
            created_at=s.created_at,
            last_used_at=s.last_used_at,
            is_current=(current_token_hash is not None and s.token_hash == current_token_hash)
        ))
    
    return result


@router.delete("/sessions/{session_id}")
def revoke_single_session(
    session_id: int,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Revokes a specific session belonging to the user.
    """
    session_rec = db.query(UserSession).filter(
        UserSession.id == session_id,
        UserSession.user_id == current_user.id,
        UserSession.revoked_at.is_(None)
    ).first()
    
    if not session_rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active session not found.")
    
    now = datetime.now(timezone.utc)
    session_rec.revoked_at = now
    
    # Check if revoking current session
    raw_refresh_token = request.cookies.get("refresh_token")
    if raw_refresh_token and session_rec.token_hash == hash_token_sha256(raw_refresh_token):
        _clear_auth_cookies(response)
    
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    audit_service.log_event(
        db=db,
        event_type="AUTH_SESSION_REVOKED",
        user_id=current_user.id,
        ip_address=client_ip,
        user_agent=user_agent,
        resource_type="UserSession",
        resource_id=str(session_id)
    )
    
    db.commit()
    return {"message": "Session revoked successfully."}
