"""
Network Scanner API Router
Platform: Nova Cyber Spark™
Founder & Architect: Pranay Kumar Mallem

Endpoints for running authorized network scans, retrieving real scan results ("Call Results"),
viewing finding explanations, and downloading dynamic ReportLab PDF reports.
"""
import uuid
import time
import json
import logging
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from pydantic import BaseModel, Field, ConfigDict, computed_field
from sqlalchemy.orm import Session

from app.database.base import get_db
from app.models.user import User
from app.models.scan import Scan
from app.models.event import ScanEvent, Finding
from app.models.audit import AuditLog
from app.api.deps import get_current_user, require_role
from app.services.scanner_service import execute_network_scan
from app.services.pdf_report_service import generate_scan_pdf
from app.services.audit_service import log_audit_event

logger = logging.getLogger("nova.scans")
router = APIRouter(prefix="/api/scans", tags=["Network Scanner"])


# ─── Pydantic Schemas ─────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    target: str = Field(default="127.0.0.1", description="Target IP, hostname, or CIDR range (e.g. 192.168.1.0/24)")
    scan_type: str = Field(default="standard", description="Scan mode: fast, standard, full")
    timezone: Optional[str] = Field(default="UTC", description="Client timezone")


class ScanSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: str
    target: str
    scan_type: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = 0.0
    timezone: Optional[str] = "UTC"
    hosts_discovered: Optional[int] = 0
    open_ports_count: Optional[int] = 0
    services_count: Optional[int] = 0
    potential_findings_count: Optional[int] = 0
    highest_severity: Optional[str] = "INFO"
    created_at: Optional[datetime] = None

    # Aliases serialized in API response
    @computed_field
    @property
    def scan_started_at(self) -> Optional[datetime]:
        return self.started_at

    @computed_field
    @property
    def scan_completed_at(self) -> Optional[datetime]:
        return self.completed_at

    @computed_field
    @property
    def scan_duration(self) -> float:
        return self.duration_seconds or 0.0

    @computed_field
    @property
    def scan_status(self) -> str:
        return self.status


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/run", response_model=dict, status_code=status.HTTP_201_CREATED)
async def run_network_scan(
    payload: ScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["ADMIN", "ANALYST"]))
):
    """
    Executes a safe, non-intrusive network scan on the specified target,
    computes finding explanations, persists events and findings, and returns complete telemetry.
    """
    scan_uuid = f"SCAN-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    start_dt = datetime.utcnow()
    
    # Create initial record
    scan_record = Scan(
        scan_id=scan_uuid,
        user_id=current_user.id,
        target=payload.target,
        scan_type=payload.scan_type,
        status="running",
        started_at=start_dt,
        timezone=getattr(payload, "timezone", None) or "UTC"
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    # Log initial scan start audit
    log_audit_event(
        db=db,
        event_type="SCAN_STARTED",
        user_id=current_user.id,
        resource_type="scan",
        resource_id=scan_uuid,
        ip_address=request.client.host if request.client else "127.0.0.1",
        metadata={"target": payload.target, "scan_type": payload.scan_type, "started_at": start_dt.isoformat()},
    )

    try:
        results = await execute_network_scan(payload.target, payload.scan_type)
        
        scan_record.status = "completed"
        scan_record.completed_at = datetime.utcnow()
        scan_record.duration_seconds = results.get("duration_seconds", 0.0)
        scan_record.hosts_discovered = results.get("hosts_discovered", 0)
        scan_record.open_ports_count = results.get("open_ports_count", 0)
        scan_record.services_count = results.get("services_count", 0)
        scan_record.potential_findings_count = results.get("potential_findings_count", 0)
        scan_record.highest_severity = results.get("highest_severity", "INFO")
        scan_record.results_data = results

        # Persist ScanEvents
        raw_events = results.get("events", [])
        scan_event_objects = []
        for e in raw_events:
            se = ScanEvent(
                event_id=e.get("event_id") or f"SEV-{uuid.uuid4().hex[:8]}",
                scan_id=scan_uuid,
                timestamp=e.get("timestamp", time.time() if "time" in globals() else 0.0),
                timestamp_str=e.get("timestamp_str"),
                event_type=e.get("event_type", "INFO"),
                severity=e.get("severity", "INFO"),
                source_ip=e.get("source_ip"),
                destination_ip=e.get("destination_ip"),
                source_port=e.get("source_port"),
                destination_port=e.get("destination_port"),
                protocol=e.get("protocol", "TCP"),
                short_explanation=e.get("short_explanation", ""),
                observation=e.get("observation"),
                analysis=e.get("analysis"),
                recommendation=e.get("recommendation"),
                evidence=e.get("evidence", {}),
            )
            scan_event_objects.append(se)

        if scan_event_objects:
            db.bulk_save_objects(scan_event_objects)

        # Persist Findings
        raw_findings = results.get("findings", [])
        finding_objects = []
        for f in raw_findings:
            fo = Finding(
                finding_id=f"{scan_uuid}-{f.get('finding_id', uuid.uuid4().hex[:6])}",
                scan_id=scan_uuid,
                host=f.get("host", payload.target),
                hostname=f.get("hostname"),
                port=f.get("port"),
                protocol=f.get("protocol", "TCP"),
                service=f.get("service"),
                severity=f.get("severity", "INFO"),
                category=f.get("category", "Services"),
                title=f.get("title", "Finding"),
                observation=f.get("description", ""),
                analysis=f.get("risk_reasoning"),
                recommendation=f.get("recommended_action"),
                investigation_steps=f.get("investigation_steps"),
                learn_more=f.get("learn_more", {}),
            )
            finding_objects.append(fo)

        if finding_objects:
            db.bulk_save_objects(finding_objects)

        db.commit()
        db.refresh(scan_record)

        log_audit_event(
            db=db,
            event_type="SCAN_COMPLETED",
            user_id=current_user.id,
            resource_type="scan",
            resource_id=scan_uuid,
            ip_address=request.client.host if request.client else "127.0.0.1",
            metadata={
                "target": payload.target,
                "duration_seconds": scan_record.duration_seconds,
                "hosts": scan_record.hosts_discovered,
                "open_ports": scan_record.open_ports_count,
                "findings": scan_record.potential_findings_count,
                "highest_severity": scan_record.highest_severity,
            },
        )

        return {
            "message": "Network scan completed successfully.",
            "scan_id": scan_uuid,
            "scan": {
                "id": scan_record.id,
                "scan_id": scan_record.scan_id,
                "target": scan_record.target,
                "scan_type": scan_record.scan_type,
                "status": scan_record.status,
                "started_at": scan_record.started_at.isoformat() if scan_record.started_at else None,
                "completed_at": scan_record.completed_at.isoformat() if scan_record.completed_at else None,
                "scan_started_at": scan_record.started_at.isoformat() if scan_record.started_at else None,
                "scan_completed_at": scan_record.completed_at.isoformat() if scan_record.completed_at else None,
                "duration_seconds": scan_record.duration_seconds,
                "scan_duration": scan_record.duration_seconds,
                "timezone": scan_record.timezone,
                "hosts_discovered": scan_record.hosts_discovered,
                "open_ports_count": scan_record.open_ports_count,
                "services_count": scan_record.services_count,
                "potential_findings_count": scan_record.potential_findings_count,
                "highest_severity": scan_record.highest_severity,
            },
            "results": results
        }

    except Exception as e:
        scan_record.status = "failed"
        scan_record.error_message = str(e)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unable to complete network scan: {str(e)}"
        )


@router.get("", response_model=List[ScanSummaryResponse])
def list_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lists network scans owned by the user (or all scans for admins)."""
    if current_user.role == "ADMIN":
        scans = db.query(Scan).order_by(Scan.id.desc()).limit(50).all()
    else:
        scans = db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.id.desc()).limit(50).all()
    return scans


@router.get("/{scan_id}", response_model=dict)
def get_scan_detail(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves full scan metadata and findings."""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    # IDOR Protection
    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized access to scan record.")

    return {
        "id": scan.id,
        "scan_id": scan.scan_id,
        "target": scan.target,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "scan_status": scan.status,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "scan_started_at": scan.started_at,
        "scan_completed_at": scan.completed_at,
        "duration_seconds": scan.duration_seconds,
        "scan_duration": scan.duration_seconds,
        "timezone": scan.timezone or "UTC",
        "hosts_discovered": scan.hosts_discovered,
        "open_ports_count": scan.open_ports_count,
        "services_count": scan.services_count,
        "potential_findings_count": scan.potential_findings_count,
        "highest_severity": scan.highest_severity or "INFO",
        "results": scan.results_data or {}
    }


@router.get("/{scan_id}/timeline", response_model=dict)
def get_scan_timeline(
    scan_id: str,
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns ordered chronological ScanEvents for a specific scan.
    Supports filtering by severity and event_type.
    """
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized access to scan timeline.")

    q = db.query(ScanEvent).filter(ScanEvent.scan_id == scan_id)
    if severity and severity.upper() != "ALL":
        q = q.filter(ScanEvent.severity == severity.upper())
    if event_type and event_type.lower() != "all":
        q = q.filter(ScanEvent.event_type == event_type.upper())

    events = q.order_by(ScanEvent.timestamp.asc()).all()

    # Fallback for historical scans
    if not events and scan.results_data and "events" in scan.results_data:
        raw_events = scan.results_data["events"]
        if severity and severity.upper() != "ALL":
            raw_events = [e for e in raw_events if e.get("severity", "").upper() == severity.upper()]
        if event_type and event_type.lower() != "all":
            raw_events = [e for e in raw_events if e.get("event_type", "").upper() == event_type.upper()]
        return {"scan_id": scan_id, "total": len(raw_events), "events": raw_events}

    return {
        "scan_id": scan_id,
        "total": len(events),
        "events": [e.to_dict() for e in events]
    }


@router.get("/{scan_id}/results", response_model=dict)
def get_scan_results_call(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    'Call Results' option: Retrieves the latest, actual scan results and finding explanations.
    """
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized access to scan results.")

    if not scan.results_data:
        raise HTTPException(status_code=400, detail="Scan results are not yet available or failed.")

    return {
        "scan_id": scan.scan_id,
        "target": scan.target,
        "status": scan.status,
        "results": scan.results_data
    }


@router.get("/{scan_id}/report", response_model=dict)
def get_scan_report_preview(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns structured report object for frontend report preview."""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized access to scan report.")

    if not scan.results_data:
        raise HTTPException(status_code=400, detail="Scan results are not available.")

    return {
        "scan_id": scan.scan_id,
        "platform": "Nova Cyber Spark™ Network Traffic Investigation & Analysis",
        "founder": "Pranay Kumar Mallem",
        "analyst": current_user.email,
        "report_generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan_data": scan.results_data
    }


@router.get("/{scan_id}/report/pdf")
def download_scan_pdf_report(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generates and returns dynamic, publication-grade PDF report using ReportLab.
    Enforces authentication, IDOR checks, and writes to audit log.
    """
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    # IDOR Protection
    if current_user.role != "ADMIN" and scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized access to scan report.")

    if not scan.results_data:
        raise HTTPException(status_code=400, detail="Scan results are not available for PDF generation.")

    try:
        scan_data = scan.results_data
        if isinstance(scan_data, str):
            scan_data = json.loads(scan_data)

        pdf_bytes = generate_scan_pdf(
            scan_data=scan_data,
            scan_id=scan.scan_id,
            analyst_email=current_user.email
        )

        # Log audit event
        log_audit_event(
            db=db,
            event_type="REPORT_GENERATED",
            user_id=current_user.id,
            resource_type="scan_report",
            resource_id=scan.scan_id,
            ip_address=request.client.host if request.client else "127.0.0.1",
            metadata={"format": "pdf"},
        )

        filename = f"Nova_Cyber_Spark_{scan.scan_id}_Report_{datetime.utcnow().strftime('%Y-%m-%d')}.pdf"

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "application/pdf"
            }
        )
    except Exception as e:
        logger.error(f"Failed to generate scan PDF report for {scan_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Unable to generate the PDF report: {str(e)}"
        )
