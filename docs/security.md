# Enterprise Security Architecture & Threat Model

## 1. Overview
The **Network Traffic Investigation & Analysis (NTIA) Platform** is an enterprise-grade platform built for SOC analysts, incident response teams, and security researchers. This document outlines the security architecture, threat model, authorization boundaries, and defense-in-depth controls implemented across the system.

---

## 2. Authentication & Credential Security

### 2.1 Password Hashing with Argon2id
All passwords are hashed using **Argon2id** (via `argon2-cffi`), the winner of the Password Hashing Competition (PHC) and recommended standard by OWASP and NIST.
- **Algorithm**: Argon2id (`v=19`)
- **Memory Cost**: 65,536 KiB (64 MB)
- **Time Cost (Iterations)**: 3 passes
- **Parallelism**: 4 lanes
- **Timing Attack Mitigation**: When a user is not found during login, a dummy Argon2id hash verification is executed to maintain consistent response times and prevent email enumeration.

### 2.2 Password Complexity Policy
The platform strictly rejects weak or compromised passwords during registration, password changes, and password resets:
- Minimum length: **12 characters** (maximum 128)
- Requires at least one uppercase letter (`[A-Z]`)
- Requires at least one lowercase letter (`[a-z]`)
- Requires at least one numeric digit (`[0-9]`)
- Requires at least one special symbol (`[!@#$%^&*...]`)
- Blacklist check against common dictionary passwords (e.g., `password123`, `admin123456`)
- Similarity check ensuring the password does not contain the user's name or email handle.

### 2.3 Account Lockout & Brute-Force Defense
- **Threshold**: 5 consecutive failed login attempts locks the account for **15 minutes**.
- **Lockout Tracking**: Recorded per-user in `users.failed_login_attempts` and `users.locked_until`.
- **IP Rate Limiting**: In-memory sliding-window rate limiters prevent distributed brute-force attacks.
- **Security Alerts**: Automatically dispatches a security alert email when an account is locked or a new IP signs in.

---

## 3. Token & Session Management

### 3.1 Token Separation
| Token Type | Storage / Transport | Expiry | Purpose |
| :--- | :--- | :--- | :--- |
| **Access Token** | In-Memory (JavaScript variable) | 15 Minutes | Stateless authorization bearer header (`Authorization: Bearer <token>`) |
| **Refresh Token** | Secure `HttpOnly` Cookie (`/api/auth`) | 7 Days | Stateful session renewal and token rotation |
| **CSRF Token** | Client Cookie & `X-CSRF-Token` Header | Session | Double-submit protection against cross-site request forgery |
| **Verification Token** | Single-Use SHA-256 Hash in DB | 24 Hours | User email address verification |
| **Reset Token** | Single-Use SHA-256 Hash in DB | 1 Hour | Password recovery workflow |

### 3.2 Token Storage Security
- Long-lived tokens are **never stored in `localStorage` or `sessionStorage`**, eliminating token theft via Cross-Site Scripting (XSS).
- Refresh tokens are transmitted solely in `HttpOnly`, `SameSite=Lax` (or `Strict`), and `Secure` (HTTPS) cookies.
- Raw refresh tokens are never persisted in the database; only cryptographically strong SHA-256 hashes are stored in `user_sessions.token_hash`.

### 3.3 Universal Logout ("Logout All Devices")
Revoking sessions invalidates all database records in `user_sessions` for that user (`revoked_at = NOW()`), immediately preventing any existing refresh tokens from obtaining new access tokens.

---

## 4. Role-Based Access Control (RBAC) & IDOR Defense

### 4.1 RBAC Roles Matrix
| Action / Endpoint | VIEWER | ANALYST | ADMIN |
| :--- | :---: | :---: | :---: |
| View Own & Legacy Investigations | ✅ | ✅ | ✅ |
| View Other Users' Investigations | ❌ | ❌ | ✅ |
| Upload & Analyze PCAPs | ❌ | ✅ | ✅ |
| Update Alert Investigation Status | ❌ | ✅ | ✅ |
| Download PCAP Files & Reports | ✅ (Authorized Only) | ✅ (Authorized Only) | ✅ |
| Delete Investigations | ❌ | ✅ (Own Only) | ✅ |
| Manage User Roles & Accounts | ❌ | ❌ | ✅ |
| Access Security Audit Logs | ❌ | ❌ | ✅ |
| Modify Heuristic & Security Settings | ❌ | ❌ | ✅ |

### 4.2 Insecure Direct Object Reference (IDOR / BOLA) Prevention
Backend endpoints authoritative checks ensure that every resource access (`/api/investigations/{id}/*`) verifies:
```python
if inv.user_id is not None and inv.user_id != current_user.id and current_user.role != "ADMIN":
    raise HTTPException(status_code=403, detail="Access denied: You do not have permission to access this investigation.")
```
Users cannot access another analyst's PCAP, alerts, conversations, or reports by manipulating URLs.

---

## 5. PCAP & Subprocess Hardening

### 5.1 Untrusted Input Handling
PCAP files uploaded to the platform are treated as untrusted binary input:
1. **Filename Sanitization**: User-supplied filenames are replaced with random UUIDs on disk (e.g., `3f29b47e-8a12-4c2d-90cf-3b91a8e4125b.pcap`) to eliminate path traversal attacks (`../../`).
2. **Magic Byte Verification**: Pre-flight verification checks file headers against valid PCAP (`0xa1b2c3d4`, `0xd4c3b2a1`, `0xa1b23c4d`) and PCAPNG (`0x0a0d0d0a`) magic signatures.
3. **Size Limits**: Strict 100 MB default ceiling enforced during streaming chunk writes.
4. **Execution Prevention**: Upload directories are non-executable.

### 5.2 Safe TShark Subprocess Invocations
- **No Shell Execution**: `os.system()` and `subprocess.Popen(..., shell=True)` are strictly prohibited.
- **Argument Arrays**: All CLI invocations use explicit string arrays with sanitized paths.
- **Process Timeouts**: Subprocesses enforce a 60-second execution timeout.
- **Controlled Environment**: System environment variables are stripped and controlled.

---

## 6. CSRF & Security Headers

### 6.1 Double-Submit Cookie CSRF Defense
State-modifying API requests (`POST`, `PUT`, `PATCH`, `DELETE`) require a valid `X-CSRF-Token` header matching the client-accessible `csrf_token` cookie.

### 6.2 HTTP Security Headers
Every HTTP response carries hardened headers:
- `Content-Security-Policy`: Restricts scripts and styles to `'self'` and approved fonts.
- `X-Content-Type-Options: nosniff`: Prevents MIME-sniffing exploits.
- `X-Frame-Options: DENY`: Prevents clickjacking.
- `Referrer-Policy: strict-origin-when-cross-origin`: Minimizes referrer information leakage.
- `Permissions-Policy`: Disables geolocation, camera, microphone, and payment APIs.
- `Strict-Transport-Security`: Enforces HTTPS (enabled when `COOKIE_SECURE=true`).

---

## 7. Security Audit Logging
The `audit_logs` table records an append-only timeline of security events:
- Authentication successes, failures, and account lockouts.
- Registration, verification, password changes, and password resets.
- Session creation and session revocation.
- PCAP uploads, investigation deletions, and report downloads.
- Role modifications and security policy updates.

Sensitive data (passwords, JWT secrets, raw tokens) are **automatically redacted** and never written to logs.
