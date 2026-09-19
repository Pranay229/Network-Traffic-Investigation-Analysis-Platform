# Authentication & Session Security Flow

This document details the exact sequence of events for user registration, verification, authentication, session renewal, and revocation in the NTIA Platform.

---

## 1. Registration Flow (`POST /api/auth/register`)

```
User (Browser)               FastAPI Backend                    Database / Email Service
     │                              │                                       │
     ├─── Full Name, Email, ───────>│                                       │
     │    Password, Confirm         │── Validate email & password strength  │
     │                              │── Check if user exists (User table) ──>│
     │                              │── Hash password with Argon2id         │
     │                              │── Create User (is_verified = False) ──>│
     │                              │── Generate random 48-byte token       │
     │                              │── Store SHA-256(token) in tokens ────>│
     │                              │── Log AUTH_REGISTER event ───────────>│
     │                              │── Dispatch Email (or Dev Console) ───>│
     │<── 201 Created ──────────────┤                                       │
     │    ("Please verify email")   │                                       │
```

---

## 2. Email Verification Flow (`GET /api/auth/verify-email?token=...`)

```
User (Browser Link)          FastAPI Backend                        Database
     │                              │                                   │
     ├─── GET /verify-email?token ─>│                                   │
     │                              │── Compute SHA-256(token)          │
     │                              │── Verify token in DB & not expired│──>
     │                              │── Mark token as used              │──>
     │                              │── Set user.is_email_verified=True │──>
     │                              │── Log AUTH_EMAIL_VERIFIED event ──>│
     │<── 200 OK ───────────────────┤                                   │
```

---

## 3. Login Flow (`POST /api/auth/login`)

```
User (Browser)               FastAPI Backend                        Database
     │                              │                                   │
     ├─── Email, Password, ────────>│                                   │
     │    RememberMe                │── Check IP & Account Lockout ────>│
     │                              │── Lookup User by Email ──────────>│
     │                              │── Verify Argon2id Password Hash   │
     │                              │── Reset failed_login_attempts     │──>
     │                              │── Generate 15-min JWT Access Token│
     │                              │── Generate 64-byte Refresh Token  │
     │                              │── Create UserSession (SHA-256) ──>│
     │                              │── Generate CSRF Double-Submit Token
     │                              │── Log AUTH_LOGIN_SUCCESS event ───>│
     │<── 200 OK ───────────────────┤                                   │
     │    Body: { access_token,     │
     │            csrf_token, user }│
     │    Set-Cookie: HttpOnly      │
     │      refresh_token (7d)      │
     │    Set-Cookie: csrf_token    │
```

---

## 4. Silent Token Refresh & Rotation (`POST /api/auth/refresh`)

```
Axios Interceptor            FastAPI Backend                        Database
     │                              │                                   │
     ├─── POST /auth/refresh ──────>│                                   │
     │    (HttpOnly refresh cookie) │── Compute SHA-256(cookie)         │
     │                              │── Find active UserSession ───────>│
     │                              │── Verify session not revoked/exp. │
     │                              │── Generate NEW Refresh Token (Rot.)
     │                              │── Update session token_hash ─────>│
     │                              │── Generate NEW Access Token (15m) │
     │                              │── Generate NEW CSRF Token         │
     │<── 200 OK ───────────────────┤                                   │
     │    Body: { access_token,     │
     │            csrf_token, user }│
     │    Set-Cookie: NEW HttpOnly  │
     │      refresh_token           │
```

---

## 5. Universal Logout ("Logout All Devices") (`POST /api/auth/logout-all`)

```
User (Browser)               FastAPI Backend                        Database
     │                              │                                   │
     ├─── POST /auth/logout-all ───>│                                   │
     │    (Bearer Auth + CSRF)      │── Mark all active UserSessions    │
     │                              │   for user as revoked_at = NOW() ─>│
     │                              │── Clear HttpOnly refresh cookie   │
     │                              │── Clear csrf_token cookie         │
     │                              │── Log AUTH_LOGOUT_ALL_DEVICES ────>│
     │<── 200 OK ───────────────────┤                                   │
```

---

## 6. Password Reset Flow

1. **Request Reset (`POST /api/auth/forgot-password`)**:
   - Takes email address.
   - Always returns `"If an active account exists, instructions have been sent"` to prevent email enumeration.
   - If account exists: generates single-use 48-byte token (1-hour expiration) and sends recovery email.
2. **Submit Reset (`POST /api/auth/reset-password`)**:
   - Validates password complexity policy.
   - Re-hashes password with Argon2id.
   - Marks reset token as used.
   - **Immediately revokes all active user sessions across all devices** for security containment.
