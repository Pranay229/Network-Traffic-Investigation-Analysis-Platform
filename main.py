"""
Root entrypoint for Cloud Deployments (Render, Railway, Fly.io, etc.)
Adds backend/ to sys.path and exposes the FastAPI app.
"""
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.main import app

__all__ = ["app"]
