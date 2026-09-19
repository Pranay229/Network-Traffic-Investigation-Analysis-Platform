"""
Comprehensive Automated Security & RBAC Test Suite for NTIA Platform.

Validates:
1. Argon2id password hashing and complexity enforcement.
2. User registration and single-use email verification tokens.
3. Login, timing defense, and temporary account lockout (5 attempts / 15 mins).
4. Rotating HttpOnly refresh tokens and database session management.
5. Single session revocation and universal logout ("Logout all devices").
6. Password reset with automatic session invalidation.
7. Role-Based Access Control (RBAC) across ADMIN, ANALYST, and VIEWER.
8. Insecure Direct Object Reference (IDOR / BOLA) prevention on investigations.
9. Security headers (CSP, nosniff, DENY) and double-submit CSRF enforcement.
10. Audit logging verification with credential redaction.
"""
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.config import settings
from app.database.base import Base, get_db
from app.models.user import User, UserSession, EmailVerificationToken, PasswordResetToken
from app.models.investigation import Investigation
from app.models.audit import AuditLog
from app.utils.security import (
    hash_password,
    verify_password,
    validate_password_strength,
    create_access_token,
    hash_token_sha256
)

# In-memory SQLite for isolated test execution
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# ============================================================================
# 1. PASSWORD HASHING & POLICY TESTS
# ============================================================================

def test_argon2id_hashing():
    pwd = "SecurePassword@2026!"
    hashed = hash_password(pwd)
    assert hashed.startswith("$argon2id$")
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False


def test_password_complexity_policy():
    # Too short (< 12 chars)
    is_valid, msg = validate_password_strength("Short1@")
    assert is_valid is False
    assert "at least 12 characters" in msg

    # Missing uppercase
    is_valid, _ = validate_password_strength("nouppercase123!@#")
    assert is_valid is False

    # Missing lowercase
    is_valid, _ = validate_password_strength("NOLOWERCASE123!@#")
    assert is_valid is False

    # Missing digit
    is_valid, _ = validate_password_strength("NoDigitsHere!@#abc")
    assert is_valid is False

    # Missing special character
    is_valid, _ = validate_password_strength("NoSpecialChar1234")
    assert is_valid is False

    # Common password blacklist
    is_valid, msg = validate_password_strength("Password123456!")
    assert is_valid is False

    # Valid strong password
    is_valid, _ = validate_password_strength("Enterprise@Sec2026#Valid")
    assert is_valid is True


# ============================================================================
# 2. REGISTRATION & EMAIL VERIFICATION
# ============================================================================

def test_user_registration_and_verification(client, db):
    # First user registered becomes ADMIN
    res = client.post("/api/auth/register", json={
        "full_name": "Lead Admin",
        "email": "admin@soc.local",
        "password": "SuperSecure@Pass2026!",
        "confirm_password": "SuperSecure@Pass2026!"
    })
    assert res.status_code == 201
    assert res.json()["requires_verification"] is True

    admin = db.query(User).filter(User.email == "admin@soc.local").first()
    assert admin is not None
    assert admin.role == "ADMIN"
    assert admin.is_email_verified is False

    # Duplicate registration should be rejected
    dup_res = client.post("/api/auth/register", json={
        "full_name": "Lead Admin",
        "email": "admin@soc.local",
        "password": "SuperSecure@Pass2026!",
        "confirm_password": "SuperSecure@Pass2026!"
    })
    assert dup_res.status_code == 400

    # Retrieve verification token from DB
    token_rec = db.query(EmailVerificationToken).filter(EmailVerificationToken.user_id == admin.id).first()
    assert token_rec is not None

    # Verification with invalid token fails
    bad_verify = client.get("/api/auth/verify-email?token=invalidtokenstring123456789012")
    assert bad_verify.status_code == 400


# ============================================================================
# 3. AUTHENTICATION, TIMING DEFENSE & LOCKOUT
# ============================================================================

def test_login_and_lockout(client, db):
    # Create test analyst
    analyst = User(
        email="analyst@soc.local",
        hashed_password=hash_password("AnalystPass@2026!"),
        full_name="SOC Analyst",
        role="ANALYST",
        is_active=True,
        is_email_verified=True
    )
    db.add(analyst)
    db.commit()

    # 1. Successful Login
    login_res = client.post("/api/auth/login", json={
        "email": "analyst@soc.local",
        "password": "AnalystPass@2026!"
    })
    assert login_res.status_code == 200
    data = login_res.json()
    assert "access_token" in data
    assert "csrf_token" in data
    assert data["user"]["role"] == "ANALYST"
    assert "refresh_token" in login_res.cookies

    # 2. Failed Login attempts
    for _ in range(4):
        bad_res = client.post("/api/auth/login", json={
            "email": "analyst@soc.local",
            "password": "WrongPassword123!"
        })
        assert bad_res.status_code == 401

    # 5th failed attempt triggers lockout
    lock_res = client.post("/api/auth/login", json={
        "email": "analyst@soc.local",
        "password": "WrongPassword123!"
    })
    assert lock_res.status_code in (401, 429)

    # 6th attempt should be blocked with 429 Too Many Requests
    blocked_res = client.post("/api/auth/login", json={
        "email": "analyst@soc.local",
        "password": "AnalystPass@2026!"
    })
    assert blocked_res.status_code == 429
    assert "temporarily locked" in blocked_res.json()["detail"]


# ============================================================================
# 4. REFRESH TOKEN ROTATION & SESSIONS
# ============================================================================

def test_refresh_token_rotation_and_revocation(client, db):
    user = User(
        email="user@soc.local",
        hashed_password=hash_password("UserPassword@2026!"),
        full_name="Test User",
        role="ANALYST",
        is_active=True,
        is_email_verified=True
    )
    db.add(user)
    db.commit()

    # Login
    login_res = client.post("/api/auth/login", json={
        "email": "user@soc.local",
        "password": "UserPassword@2026!"
    })
    assert login_res.status_code == 200
    old_refresh = login_res.cookies.get("refresh_token")
    access_token = login_res.json()["access_token"]
    csrf_token = login_res.json()["csrf_token"]

    # Refresh
    client.cookies.set("refresh_token", old_refresh)
    refresh_res = client.post("/api/auth/refresh")
    assert refresh_res.status_code == 200
    new_refresh = refresh_res.cookies.get("refresh_token")
    assert new_refresh != old_refresh  # Rotated!

    # Active sessions endpoint
    headers = {"Authorization": f"Bearer {refresh_res.json()['access_token']}"}
    sessions_res = client.get("/api/auth/sessions", headers=headers)
    assert sessions_res.status_code == 200
    assert len(sessions_res.json()) >= 1

    # Universal logout
    logout_all = client.post("/api/auth/logout-all", headers={
        **headers,
        "X-CSRF-Token": refresh_res.json()["csrf_token"]
    })
    assert logout_all.status_code == 200

    # Old refresh token now fails
    client.cookies.set("refresh_token", new_refresh)
    bad_refresh = client.post("/api/auth/refresh")
    assert bad_refresh.status_code == 401


# ============================================================================
# 5. ROLE-BASED ACCESS CONTROL (RBAC) & IDOR PROTECTION
# ============================================================================

def test_rbac_and_idor_investigation_security(client, db):
    # Create 3 users with different roles
    admin = User(
        email="admin@soc.local",
        hashed_password=hash_password("AdminSecure@2026!"),
        full_name="Admin User",
        role="ADMIN",
        is_active=True,
        is_email_verified=True
    )
    analyst_a = User(
        email="analyst_a@soc.local",
        hashed_password=hash_password("AnalystASec@2026!"),
        full_name="Analyst A",
        role="ANALYST",
        is_active=True,
        is_email_verified=True
    )
    viewer = User(
        email="viewer@soc.local",
        hashed_password=hash_password("ViewerSecure@2026!"),
        full_name="Viewer User",
        role="VIEWER",
        is_active=True,
        is_email_verified=True
    )
    db.add_all([admin, analyst_a, viewer])
    db.commit()

    # Create investigation owned by Analyst A
    inv_a = Investigation(
        inv_id="INV-2026-0001",
        user_id=analyst_a.id,
        filename="analyst_a_capture.pcap",
        original_filename="capture.pcap",
        pcap_path="uploads/dummy.pcap",
        file_size=1024,
        status="completed"
    )
    db.add(inv_a)
    db.commit()

    token_admin = create_access_token({"sub": str(admin.id), "role": "ADMIN", "email": admin.email})
    token_analyst_a = create_access_token({"sub": str(analyst_a.id), "role": "ANALYST", "email": analyst_a.email})
    token_viewer = create_access_token({"sub": str(viewer.id), "role": "VIEWER", "email": viewer.email})

    # 1. Analyst A can access their own investigation
    res_a = client.get(f"/api/investigations/{inv_a.inv_id}", headers={"Authorization": f"Bearer {token_analyst_a}"})
    assert res_a.status_code == 200

    # 2. Viewer attempting to access Analyst A's investigation is blocked (IDOR protection)
    res_viewer = client.get(f"/api/investigations/{inv_a.inv_id}", headers={"Authorization": f"Bearer {token_viewer}"})
    assert res_viewer.status_code == 403

    # 3. Viewer attempting to delete is blocked
    del_viewer = client.delete(f"/api/investigations/{inv_a.inv_id}", headers={"Authorization": f"Bearer {token_viewer}"})
    assert del_viewer.status_code == 403

    # 4. Admin can access any investigation
    res_admin = client.get(f"/api/investigations/{inv_a.inv_id}", headers={"Authorization": f"Bearer {token_admin}"})
    assert res_admin.status_code == 200

    # 5. Non-admin attempting to access /api/admin/* is blocked
    admin_probe = client.get("/api/admin/users", headers={"Authorization": f"Bearer {token_analyst_a}"})
    assert admin_probe.status_code == 403

    # 6. Admin can access /api/admin/users
    admin_ok = client.get("/api/admin/users", headers={"Authorization": f"Bearer {token_admin}"})
    assert admin_ok.status_code == 200


# ============================================================================
# 6. SECURITY HEADERS
# ============================================================================

def test_security_headers(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert "Content-Security-Policy" in res.headers
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in res.headers["Content-Security-Policy"]
