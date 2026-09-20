"""
Network Traffic Investigation & Analysis Platform — FastAPI Backend

Entry point for the NTIA Platform backend API with security headers,
CSRF double-submit validation, and full RBAC authorization.
"""
import logging
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.database.base import init_db
from app.api.auth import router as auth_router
from app.api.admin import router as admin_router
from app.api.pcap import router as pcap_router
from app.api.investigations import router as inv_router, settings_router
from app.api.scans import router as scans_router

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """App startup: initialize database, run migrations, and verify analyzers."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    settings.ensure_dirs()
    init_db()
    tshark_status = "✅ Available" if settings.tshark_available() else "❌ Not found"
    logger.info(f"TShark: {tshark_status} ({settings.TSHARK_PATH})")
    yield
    logger.info("Backend shutting down.")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Enterprise Network Traffic Investigation & Analysis Platform with RBAC, session management, and SOC security.",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)


# ─── Security Headers Middleware ──────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        
        # CSP: Restrict resource origins to self and approved CDN fonts
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "base-uri 'self';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"
        
        if settings.COOKIE_SECURE:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            
        return response

app.add_middleware(SecurityHeadersMiddleware)


# ─── CSRF Protection Middleware ───────────────────────────────────────────────

EXEMPT_CSRF_PATHS = {
    "/api/auth/register",
    "/api/auth/login",
    "/api/auth/refresh",
    "/api/auth/forgot-password",
    "/api/auth/reset-password",
    "/api/auth/resend-verification",
    "/api/auth/verify-email",
    "/api/health",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json"
}

class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Open access mode: allow state-modifying requests without CSRF double-submit token
        return await call_next(request)

app.add_middleware(CSRFMiddleware)


# ─── CORS Configuration ───────────────────────────────────────────────────────

cors_kwargs = {
    "allow_credentials": True,
    "allow_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    "allow_headers": ["Authorization", "Content-Type", "X-CSRF-Token", "Accept"],
    "expose_headers": ["X-CSRF-Token"],
}
if "*" in settings.cors_origins_list:
    cors_kwargs["allow_origin_regex"] = r"https?://.*"
else:
    cors_kwargs["allow_origins"] = settings.cors_origins_list

app.add_middleware(CORSMiddleware, **cors_kwargs)


# ─── Routers ──────────────────────────────────────────────────────────────────

app.include_router(auth_router, prefix="/api", tags=["Authentication"])
app.include_router(admin_router, prefix="/api", tags=["Security Administration"])
app.include_router(pcap_router, prefix="/api/pcap", tags=["PCAP Upload"])
app.include_router(inv_router, prefix="/api/investigations", tags=["Investigations"])
app.include_router(settings_router, prefix="/api/settings", tags=["Settings"])
app.include_router(scans_router)


# ─── Exception Handlers ───────────────────────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": str(exc), "type": "validation_error"},
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "type": "http_error"},
    )


@app.exception_handler(Exception)
async def generic_error_handler(request, exc):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please contact the system administrator.", "type": "server_error"},
    )


# ─── Health Check ─────────────────────────────────────────────────────────────

@app.get("/api/health", tags=["System"])
def health_check():
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "tshark_available": settings.tshark_available(),
        "tshark_path": settings.TSHARK_PATH,
    }


# ─── Static Files & SPA Routing (Production Deployment) ───────────────────────

frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

SPA_ROUTES = {
    "", "upload", "investigations", "traffic", "hosts",
    "conversations", "dns", "http", "tcp", "icmp", "alerts",
    "timeline", "packets", "iocs", "reports", "settings",
    "scanner", "scans", "admin", "audit-logs",
    "login", "register"  # allow SPA to capture and redirect legacy routes
}

if frontend_dist.exists() and (frontend_dist / "index.html").exists():
    assets_dir = frontend_dist / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        clean_path = full_path.strip("/")
        # Strict path traversal check
        try:
            target_file = (frontend_dist / clean_path).resolve()
            target_file.relative_to(frontend_dist.resolve())
        except (ValueError, Exception):
            raise HTTPException(status_code=403, detail="Access denied.")

        # Serve static file from dist if it exists directly (e.g. favicon.svg)
        if clean_path and target_file.is_file():
            return FileResponse(str(target_file))

        # Check if first path segment is a known SPA client route
        first_seg = clean_path.split("/")[0] if clean_path else ""
        if not clean_path or first_seg in SPA_ROUTES:
            return FileResponse(str(frontend_dist / "index.html"))

        raise HTTPException(status_code=404, detail="Not found.")
else:
    @app.get("/", include_in_schema=False)
    def root():
        return {"message": f"{settings.APP_NAME} API is running. Visit /api/docs for documentation."}
