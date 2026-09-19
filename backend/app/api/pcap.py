"""
PCAP upload endpoint.
- Accepts .pcap and .pcapng files
- Validates file before saving
- Generates unique investigation ID
- Associates investigation with authenticated user
- Starts analysis pipeline in background
"""
import os
import uuid
import logging
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, BackgroundTasks, HTTPException, Request, Depends
from sqlalchemy.orm import Session

from app.database.base import get_db
from app.models.investigation import Investigation
from app.models.user import User
from app.config import settings
from app.services.investigation_service import run_analysis_pipeline
from app.services.audit_service import audit_service
from app.api.deps import (
    get_current_active_user,
    require_role,
    get_client_ip,
    get_user_agent
)

logger = logging.getLogger(__name__)
router = APIRouter()

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
MAX_SIZE = settings.max_upload_bytes

# Only ANALYST and ADMIN can upload PCAPs (VIEWER cannot upload)
require_uploader = require_role(["ADMIN", "ANALYST"])


def _generate_inv_id(db: Session) -> str:
    """Generate next sequential investigation ID like INV-2026-0001."""
    year = datetime.utcnow().year
    count = db.query(Investigation).count()
    return f"INV-{year}-{count + 1:04d}"


def _safe_filename(original: str) -> str:
    """Create a safe UUID-based filename preserving extension."""
    ext = Path(original).suffix.lower()
    return f"{uuid.uuid4().hex}{ext}"


@router.post("/upload")
async def upload_pcap(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_uploader)
):
    """
    Upload a PCAP or PCAPNG file and start analysis.
    Enforces analyst/admin RBAC role and records ownership.
    Returns the investigation ID immediately; analysis runs in background.
    """
    # Validate extension before reading any data
    original_name = file.filename or "unknown.pcap"
    ext = Path(original_name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type '{ext}'. Only .pcap and .pcapng files are accepted."
        )

    # Check content type (best effort — browsers may send wrong MIME)
    if file.content_type and file.content_type not in (
        "application/vnd.tcpdump.pcap",
        "application/octet-stream",
        "application/x-pcap",
        "application/pcap",
        "",
    ):
        logger.warning(f"Unusual content type: {file.content_type}")

    # Ensure upload dir exists
    upload_dir = Path(settings.UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)

    # Save file with safe UUID name (never trust user-provided filename on disk)
    safe_name = _safe_filename(original_name)
    save_path = upload_dir / safe_name

    try:
        total_bytes = 0
        with open(save_path, "wb") as out:
            while chunk := await file.read(65536):  # 64 KB chunks
                total_bytes += len(chunk)
                if total_bytes > MAX_SIZE:
                    out.close()
                    save_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large. Maximum allowed size is {settings.MAX_UPLOAD_SIZE_MB} MB."
                    )
                out.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        save_path.unlink(missing_ok=True)
        logger.error(f"File save error: {e}")
        raise HTTPException(status_code=500, detail="Failed to save uploaded file.")

    if total_bytes == 0:
        save_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Synchronous pre-flight validation (magic bytes, headers)
    from app.analyzers.pcap_validator import validate_pcap_file
    validation = validate_pcap_file(str(save_path), original_name)
    if not validation["valid"]:
        save_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=validation["error"])

    # Create investigation record associated with authenticated user
    inv_id = _generate_inv_id(db)
    investigation = Investigation(
        inv_id=inv_id,
        user_id=current_user.id,
        filename=safe_name,
        original_filename=original_name,
        pcap_path=str(save_path),
        file_size=total_bytes,
        status="pending",
        progress=0,
        current_stage="Queued for analysis",
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)

    # Security Audit Log
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    audit_service.log_event(
        db=db,
        event_type="PCAP_UPLOAD",
        user_id=current_user.id,
        ip_address=client_ip,
        user_agent=user_agent,
        resource_type="Investigation",
        resource_id=str(investigation.id),
        metadata={
            "inv_id": inv_id,
            "filename": original_name,
            "file_size": total_bytes
        }
    )
    db.commit()

    # Start background analysis
    background_tasks.add_task(
        run_analysis_pipeline,
        investigation.id,
        str(save_path),
        original_name,
    )

    logger.info(f"Created investigation {inv_id} for '{original_name}' ({total_bytes:,} bytes) by user {current_user.email}")

    return {
        "inv_id": inv_id,
        "investigation_id": investigation.id,
        "filename": original_name,
        "file_size": total_bytes,
        "status": "pending",
        "message": "File uploaded successfully. Analysis started in background.",
    }
