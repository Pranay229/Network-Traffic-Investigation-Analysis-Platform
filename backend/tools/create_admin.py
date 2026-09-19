"""
CLI Tool to initialize the database, create an administrator user,
or promote an existing user to ADMIN role.

Usage:
    python tools/create_admin.py --email admin@soc.local --name "SOC Lead Admin" --password "SecureAdmin@2026"
    python tools/create_admin.py --promote analyst@soc.local
"""
import sys
import argparse
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.database.base import SessionLocal, init_db
from app.models.user import User
from app.utils.security import hash_password, validate_password_strength


def create_or_promote_admin(email: str, full_name: str = None, password: str = None, promote_only: bool = False):
    init_db()
    db = SessionLocal()
    email_clean = email.lower().strip()

    try:
        user = db.query(User).filter(User.email == email_clean).first()

        if user:
            print(f"[*] Found existing user: {user.email} (Current Role: {user.role}, Active: {user.is_active})")
            user.role = "ADMIN"
            user.is_active = True
            user.is_email_verified = True
            if password:
                is_valid, msg = validate_password_strength(password)
                if not is_valid:
                    print(f"[-] Password rejected: {msg}")
                    return False
                user.hashed_password = hash_password(password)
                print("[+] Password updated successfully.")
            db.commit()
            print(f"[+] User '{email_clean}' is now an active ADMIN.")
            return True

        if promote_only:
            print(f"[-] User '{email_clean}' does not exist. Cannot promote.")
            return False

        if not password:
            print("[-] Error: Password is required to create a new admin user.")
            return False

        is_valid, msg = validate_password_strength(password, user_inputs=[full_name or "", email_clean])
        if not is_valid:
            print(f"[-] Password rejected: {msg}")
            return False

        name = full_name.strip() if full_name else "Administrator"
        pwd_hash = hash_password(password)

        new_admin = User(
            email=email_clean,
            hashed_password=pwd_hash,
            full_name=name,
            role="ADMIN",
            is_active=True,
            is_email_verified=True
        )
        db.add(new_admin)
        db.commit()
        print(f"[+] Successfully created new Administrator account: {email_clean}")
        return True

    except Exception as e:
        db.rollback()
        print(f"[-] Error: {e}")
        return False
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create or promote an administrator account for NTIA Platform.")
    parser.add_argument("--email", required=True, help="Administrator email address")
    parser.add_argument("--name", default="SOC Administrator", help="Full name")
    parser.add_argument("--password", help="Strong password (min 12 chars, upper, lower, digit, symbol)")
    parser.add_argument("--promote", action="store_true", help="Promote existing user to ADMIN role")

    args = parser.parse_args()
    success = create_or_promote_admin(
        email=args.email,
        full_name=args.name,
        password=args.password,
        promote_only=args.promote
    )
    sys.exit(0 if success else 1)
