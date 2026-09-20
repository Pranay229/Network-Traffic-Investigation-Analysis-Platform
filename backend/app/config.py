"""
Application configuration using pydantic-settings.
Settings are read from environment variables and the .env file.
"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

class Settings(BaseSettings):
    # App
    APP_NAME: str = "Nova Cyber Spark — Network Traffic Investigation Platform"
    APP_VERSION: str = "2026.1"
    APP_FOUNDER: str = "Pranay Kumar Mallem"
    APP_ORGANIZATION: str = "Nova Cyber Spark"
    DEBUG: bool = False
    FRONTEND_URL: str = "http://localhost:5173"

    # Database — SQLite by default, swap URL for PostgreSQL later
    DATABASE_URL: str = f"sqlite:///{DATA_DIR / 'ntia.db'}"

    # Storage
    UPLOAD_DIR: str = str(DATA_DIR / "uploads")
    REPORTS_DIR: str = str(DATA_DIR / "reports")

    # TShark — Windows default path; override via env var
    TSHARK_PATH: str = r"C:\Program Files\Wireshark\tshark.exe"

    # File upload limits
    MAX_UPLOAD_SIZE_MB: int = 500

    # CORS — comma-separated list of allowed origins
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000,http://localhost:8001,http://127.0.0.1:5173,http://127.0.0.1:8001"

    # Authentication & JWT
    JWT_SECRET_KEY: str = "ntia-dev-secret-key-change-in-production-min32chars-secure"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    VERIFICATION_TOKEN_EXPIRE_HOURS: int = 24
    PASSWORD_RESET_TOKEN_EXPIRE_HOURS: int = 1

    # Cookie Security
    COOKIE_SECURE: bool = False        # Set True in HTTPS production
    COOKIE_SAMESITE: str = "lax"       # "lax" | "strict" | "none"
    COOKIE_DOMAIN: str | None = None
    CSRF_COOKIE_NAME: str = "ntia_csrf"
    REFRESH_COOKIE_NAME: str = "ntia_refresh"

    # Account Lockout & Rate Limiting
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15
    DEFAULT_USER_ROLE: str = "ANALYST"  # "VIEWER" | "ANALYST" | "ADMIN"

    # Email / SMTP
    SMTP_ENABLED: bool = False
    SMTP_HOST: str = "smtp.example.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = "security@ntia-platform.local"
    SMTP_FROM_NAME: str = "NTIA Security Team"
    SMTP_USE_TLS: bool = True

    # Detection thresholds (all configurable)
    PORT_SCAN_MIN_PORTS: int = 10
    PORT_SCAN_TIME_WINDOW: int = 60       # seconds
    DNS_QUERY_THRESHOLD: int = 100
    ICMP_THRESHOLD: int = 100
    TCP_CONN_THRESHOLD: int = 100
    HIGH_CONN_THRESHOLD: int = 50
    LONG_DNS_QUERY_LEN: int = 50          # characters
    HIGH_SUBDOMAIN_COUNT: int = 20

    # Traffic Activity & High Traffic Detection Thresholds (Configurable)
    HIGH_PACKET_RATE_THRESHOLD: int = 500        # packets per second
    HIGH_BYTE_RATE_THRESHOLD: int = 1_000_000    # bytes per second (~1 MB/s)
    HIGH_CONNECTION_RATE_THRESHOLD: int = 20     # connections per second
    LARGE_DATA_TRANSFER_THRESHOLD: int = 10_000_000  # bytes per flow (~10 MB)

    class Config:
        env_file = ".env"
        extra = "ignore"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    def tshark_available(self) -> bool:
        if Path(self.TSHARK_PATH).is_file():
            return True
        import shutil
        found = shutil.which("tshark")
        if found:
            self.TSHARK_PATH = found
            return True
        return False

    def ensure_dirs(self) -> None:
        """Create storage directories if they don't exist."""
        for d in [self.UPLOAD_DIR, self.REPORTS_DIR, "data"]:
            Path(d).mkdir(parents=True, exist_ok=True)


settings = Settings()
