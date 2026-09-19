from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.config import settings
from app.database.base import get_db
from app.models.user import User, UserSession
from app.models.audit import AuditLog
from app.models.investigation import Investigation
from app.api.deps import (
    get_current_active_user,
    require_role,
    get_client_ip,
    get_user_agent
)
from app.services.audit_service import audit_service

router = APIRouter(prefix="/admin", tags=["Security Administration"])

# Dependency shortcut for ADMIN role
require_admin = require_role(["ADMIN"])


# ==========================================
# PYDANTIC SCHEMAS
# ==========================================

class AdminUserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    is_email_verified: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None
    last_login_ip: Optional[str] = None
    failed_login_attempts: int = 0
    active_sessions_count: int = 0

    class Config:
        from_attributes = True


class UpdateUserRoleRequest(BaseModel):
    role: str

    @field_validator("role")
    def validate_role(cls, v: str) -> str:
        v = v.upper().strip()
        if v not in ["ADMIN", "ANALYST", "VIEWER"]:
            raise ValueError("Role must be ADMIN, ANALYST, or VIEWER.")
        return v


class UpdateUserStatusRequest(BaseModel):
    is_active: bool


class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    event_type: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    resource_type: Optional[str]
    resource_id: Optional[str]
    metadata_json: Optional[Dict[str, Any]]
    created_at: datetime

    class Config:
        from_attributes = True


class SecuritySettingsResponse(BaseModel):
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    max_login_attempts: int
    lockout_duration_minutes: int
    max_pcap_size_mb: int
    cookie_secure: bool
    cookie_samesite: str
    frontend_url: str


class UpdateSecuritySettingsRequest(BaseModel):
    access_token_expire_minutes: Optional[int] = None
    refresh_token_expire_days: Optional[int] = None
    max_login_attempts: Optional[int] = None
    lockout_duration_minutes: Optional[int] = None
    max_pcap_size_mb: Optional[int] = None


# ==========================================
# ADMIN ENDPOINTS
# ==========================================

@router.get("/users", response_model=List[AdminUserResponse])
def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    role: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """
    Lists all platform users with role, status, verification status, and active session counts.
    """
    query = db.query(User)
    
    if role:
        query = query.filter(User.role == role.upper())
    
    if search:
        search_pattern = f"%{search.strip()}%"
        query = query.filter(
            (User.email.ilike(search_pattern)) | 
            (User.full_name.ilike(search_pattern))
        )
    
    users = query.order_by(User.created_at.desc()).offset(skip).limit(limit).all()
    
    result = []
    for u in users:
        active_sessions = db.query(UserSession).filter(
            UserSession.user_id == u.id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > datetime.now(timezone.utc)
        ).count()
        
        result.append(AdminUserResponse(
            id=u.id,
            email=u.email,
            full_name=u.full_name,
            role=u.role,
            is_active=u.is_active,
            is_email_verified=u.is_email_verified,
            created_at=u.created_at,
            last_login_at=u.last_login_at,
            last_login_ip=u.last_login_ip,
            failed_login_attempts=u.failed_login_attempts,
            active_sessions_count=active_sessions
        ))
    
    return result


@router.put("/users/{user_id}/role", response_model=AdminUserResponse)
def update_user_role(
    user_id: int,
    payload: UpdateUserRoleRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """
    Updates a user's RBAC role (ADMIN, ANALYST, VIEWER).
    Prevents self-demotion if it would leave the platform with no active admins.
    """
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    
    # Prevent removing last admin
    if target_user.role == "ADMIN" and payload.role != "ADMIN":
        admin_count = db.query(User).filter(User.role == "ADMIN", User.is_active == True).count()
        if admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot demote the sole active administrator account."
            )
    
    old_role = target_user.role
    target_user.role = payload.role
    
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    audit_service.log_event(
        db=db,
        event_type="ADMIN_USER_ROLE_CHANGED",
        user_id=admin_user.id,
        ip_address=client_ip,
        user_agent=user_agent,
        resource_type="User",
        resource_id=str(target_user.id),
        metadata={
            "target_user_email": target_user.email,
            "old_role": old_role,
            "new_role": payload.role
        }
    )
    
    db.commit()
    return AdminUserResponse(
        id=target_user.id,
        email=target_user.email,
        full_name=target_user.full_name,
        role=target_user.role,
        is_active=target_user.is_active,
        is_email_verified=target_user.is_email_verified,
        created_at=target_user.created_at,
        last_login_at=target_user.last_login_at,
        last_login_ip=target_user.last_login_ip,
        failed_login_attempts=target_user.failed_login_attempts,
        active_sessions_count=0
    )


@router.put("/users/{user_id}/status", response_model=AdminUserResponse)
def update_user_status(
    user_id: int,
    payload: UpdateUserStatusRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """
    Activates or deactivates a user account.
    Deactivating revokes all active sessions immediately.
    """
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    
    # Prevent self-deactivation if last admin
    if target_user.id == admin_user.id and not payload.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own administrator account."
        )
    
    target_user.is_active = payload.is_active
    
    now = datetime.now(timezone.utc)
    # If deactivating, revoke all active sessions
    if not payload.is_active:
        db.query(UserSession).filter(
            UserSession.user_id == target_user.id,
            UserSession.revoked_at.is_(None)
        ).update({"revoked_at": now})
    
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    audit_service.log_event(
        db=db,
        event_type="ADMIN_USER_STATUS_CHANGED",
        user_id=admin_user.id,
        ip_address=client_ip,
        user_agent=user_agent,
        resource_type="User",
        resource_id=str(target_user.id),
        metadata={
            "target_user_email": target_user.email,
            "new_status": "ACTIVE" if payload.is_active else "DEACTIVATED"
        }
    )
    
    db.commit()
    return AdminUserResponse(
        id=target_user.id,
        email=target_user.email,
        full_name=target_user.full_name,
        role=target_user.role,
        is_active=target_user.is_active,
        is_email_verified=target_user.is_email_verified,
        created_at=target_user.created_at,
        last_login_at=target_user.last_login_at,
        last_login_ip=target_user.last_login_ip,
        failed_login_attempts=target_user.failed_login_attempts,
        active_sessions_count=0
    )


@router.post("/users/{user_id}/revoke-sessions")
def revoke_user_sessions_admin(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """
    Admin action to revoke all active sessions for a specific user.
    """
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    
    now = datetime.now(timezone.utc)
    count = db.query(UserSession).filter(
        UserSession.user_id == target_user.id,
        UserSession.revoked_at.is_(None)
    ).update({"revoked_at": now})
    
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    audit_service.log_event(
        db=db,
        event_type="ADMIN_REVOKED_USER_SESSIONS",
        user_id=admin_user.id,
        ip_address=client_ip,
        user_agent=user_agent,
        resource_type="User",
        resource_id=str(target_user.id),
        metadata={"target_user_email": target_user.email, "revoked_count": count}
    )
    
    db.commit()
    return {"message": f"Successfully revoked {count} active sessions for {target_user.email}."}


@router.get("/audit-logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    event_type: Optional[str] = None,
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """
    Admin query endpoint for the security audit log.
    Allows SOC investigation of security events, authentication attempts, and authorization failures.
    """
    query = db.query(AuditLog)
    
    if event_type:
        query = query.filter(AuditLog.event_type == event_type.upper().strip())
    
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
        
    if ip_address:
        query = query.filter(AuditLog.ip_address == ip_address.strip())
    
    logs = query.order_by(desc(AuditLog.created_at)).offset(skip).limit(limit).all()
    result = []
    for l in logs:
        result.append(AuditLogResponse(
            id=l.id,
            user_id=l.user_id,
            event_type=l.event_type,
            ip_address=l.ip_address,
            user_agent=l.user_agent,
            resource_type=l.resource_type,
            resource_id=l.resource_id,
            metadata_json=l.metadata_dict,
            created_at=l.created_at
        ))
    return result


@router.get("/settings", response_model=SecuritySettingsResponse)
def get_security_settings(
    admin_user: User = Depends(require_admin)
):
    """
    Returns active security and session configurations.
    """
    return SecuritySettingsResponse(
        access_token_expire_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        refresh_token_expire_days=settings.REFRESH_TOKEN_EXPIRE_DAYS,
        max_login_attempts=settings.MAX_LOGIN_ATTEMPTS,
        lockout_duration_minutes=settings.LOCKOUT_DURATION_MINUTES,
        max_pcap_size_mb=settings.MAX_PCAP_SIZE_MB,
        cookie_secure=settings.COOKIE_SECURE,
        cookie_samesite=settings.COOKIE_SAMESITE,
        frontend_url=settings.FRONTEND_URL
    )


@router.put("/settings", response_model=SecuritySettingsResponse)
def update_security_settings(
    payload: UpdateSecuritySettingsRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """
    Allows administrator to dynamically update session, lockout, and upload limits.
    """
    changes = {}
    if payload.access_token_expire_minutes is not None:
        if 1 <= payload.access_token_expire_minutes <= 1440:
            settings.ACCESS_TOKEN_EXPIRE_MINUTES = payload.access_token_expire_minutes
            changes["access_token_expire_minutes"] = payload.access_token_expire_minutes
    
    if payload.refresh_token_expire_days is not None:
        if 1 <= payload.refresh_token_expire_days <= 90:
            settings.REFRESH_TOKEN_EXPIRE_DAYS = payload.refresh_token_expire_days
            changes["refresh_token_expire_days"] = payload.refresh_token_expire_days
            
    if payload.max_login_attempts is not None:
        if 3 <= payload.max_login_attempts <= 20:
            settings.MAX_LOGIN_ATTEMPTS = payload.max_login_attempts
            changes["max_login_attempts"] = payload.max_login_attempts
            
    if payload.lockout_duration_minutes is not None:
        if 1 <= payload.lockout_duration_minutes <= 1440:
            settings.LOCKOUT_DURATION_MINUTES = payload.lockout_duration_minutes
            changes["lockout_duration_minutes"] = payload.lockout_duration_minutes
            
    if payload.max_pcap_size_mb is not None:
        if 1 <= payload.max_pcap_size_mb <= 1000:
            settings.MAX_PCAP_SIZE_MB = payload.max_pcap_size_mb
            changes["max_pcap_size_mb"] = payload.max_pcap_size_mb
    
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    audit_service.log_event(
        db=db,
        event_type="ADMIN_SECURITY_SETTINGS_UPDATED",
        user_id=admin_user.id,
        ip_address=client_ip,
        user_agent=user_agent,
        metadata={"changes": changes}
    )
    
    db.commit()
    
    return SecuritySettingsResponse(
        access_token_expire_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        refresh_token_expire_days=settings.REFRESH_TOKEN_EXPIRE_DAYS,
        max_login_attempts=settings.MAX_LOGIN_ATTEMPTS,
        lockout_duration_minutes=settings.LOCKOUT_DURATION_MINUTES,
        max_pcap_size_mb=settings.MAX_PCAP_SIZE_MB,
        cookie_secure=settings.COOKIE_SECURE,
        cookie_samesite=settings.COOKIE_SAMESITE,
        frontend_url=settings.FRONTEND_URL
    )
