"""
Database engine, session factory, and declarative base.
Configured for SQLite now; switch to PostgreSQL by changing DATABASE_URL.
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

# Enable WAL mode for SQLite for better concurrent read performance
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {},
    echo=settings.DEBUG,
)

if "sqlite" in settings.DATABASE_URL:
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency: yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables and perform lightweight schema migrations."""
    # Import all models so they register with Base
    from app.models import user, audit, investigation, packet, host, conversation, record, alert, ioc, scan, event  # noqa: F401
    Base.metadata.create_all(bind=engine)

    # Backward compatibility: verify and migrate SQLite tables if missing columns
    if "sqlite" in settings.DATABASE_URL:
        try:
            with engine.connect() as conn:
                cursor = conn.connection.cursor()

                # Migrate investigations table
                cursor.execute("PRAGMA table_info(investigations)")
                inv_cols = [row[1] for row in cursor.fetchall()]
                if inv_cols:
                    if "user_id" not in inv_cols:
                        cursor.execute("ALTER TABLE investigations ADD COLUMN user_id INTEGER REFERENCES users(id)")
                    if "investigation_status" not in inv_cols:
                        cursor.execute("ALTER TABLE investigations ADD COLUMN investigation_status VARCHAR(32) DEFAULT 'OPEN'")
                    if "severity" not in inv_cols:
                        cursor.execute("ALTER TABLE investigations ADD COLUMN severity VARCHAR(20) DEFAULT 'INFO'")
                    if "related_scan_id" not in inv_cols:
                        cursor.execute("ALTER TABLE investigations ADD COLUMN related_scan_id VARCHAR(64)")
                    if "notes_json" not in inv_cols:
                        cursor.execute("ALTER TABLE investigations ADD COLUMN notes_json TEXT DEFAULT '[]'")

                # Migrate scans table
                cursor.execute("PRAGMA table_info(scans)")
                scan_cols = [row[1] for row in cursor.fetchall()]
                if scan_cols:
                    if "timezone" not in scan_cols:
                        cursor.execute("ALTER TABLE scans ADD COLUMN timezone VARCHAR(32) DEFAULT 'UTC'")
                    if "highest_severity" not in scan_cols:
                        cursor.execute("ALTER TABLE scans ADD COLUMN highest_severity VARCHAR(20)")
                    if "duration_seconds" not in scan_cols:
                        cursor.execute("ALTER TABLE scans ADD COLUMN duration_seconds FLOAT DEFAULT 0.0")
                    if "started_at" not in scan_cols:
                        cursor.execute("ALTER TABLE scans ADD COLUMN started_at DATETIME")
                    if "completed_at" not in scan_cols:
                        cursor.execute("ALTER TABLE scans ADD COLUMN completed_at DATETIME")

                # Migrate users table if exists from older version
                cursor.execute("PRAGMA table_info(users)")
                user_cols = [row[1] for row in cursor.fetchall()]
                if user_cols:
                    if "last_login_ip" not in user_cols:
                        cursor.execute("ALTER TABLE users ADD COLUMN last_login_ip VARCHAR(45)")
                    if "failed_login_attempts" not in user_cols:
                        cursor.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0")
                    if "locked_until" not in user_cols:
                        cursor.execute("ALTER TABLE users ADD COLUMN locked_until DATETIME")
                    if "is_verified" not in user_cols:
                        cursor.execute("ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT 0")

                # Migrate packets table if exists from older version
                cursor.execute("PRAGMA table_info(packets)")
                pkt_cols = [row[1] for row in cursor.fetchall()]
                if pkt_cols:
                    if "ttl" not in pkt_cols:
                        cursor.execute("ALTER TABLE packets ADD COLUMN ttl INTEGER")
                    if "window_size" not in pkt_cols:
                        cursor.execute("ALTER TABLE packets ADD COLUMN window_size INTEGER")
                    if "checksum_valid" not in pkt_cols:
                        cursor.execute("ALTER TABLE packets ADD COLUMN checksum_valid BOOLEAN")
                    if "direction" not in pkt_cols:
                        cursor.execute("ALTER TABLE packets ADD COLUMN direction VARCHAR(16)")
                    if "app_protocol" not in pkt_cols:
                        cursor.execute("ALTER TABLE packets ADD COLUMN app_protocol VARCHAR(32)")
                    if "payload_hash" not in pkt_cols:
                        cursor.execute("ALTER TABLE packets ADD COLUMN payload_hash VARCHAR(64)")
                    if "is_flagged" not in pkt_cols:
                        cursor.execute("ALTER TABLE packets ADD COLUMN is_flagged BOOLEAN DEFAULT 0")
                    if "analyst_note" not in pkt_cols:
                        cursor.execute("ALTER TABLE packets ADD COLUMN analyst_note TEXT")
                    if "created_at" not in pkt_cols:
                        cursor.execute("ALTER TABLE packets ADD COLUMN created_at DATETIME")

                conn.connection.commit()
                cursor.close()
        except Exception:
            pass
