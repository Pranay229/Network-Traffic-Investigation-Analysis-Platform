"""
Production Server Runner for Network Traffic Investigation & Analysis Platform
Runs FastAPI + Built Frontend on a single unified port (default 8000).
"""
import os
import sys
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
FRONTEND_DIR = ROOT_DIR / "frontend"
DIST_DIR = FRONTEND_DIR / "dist"

def build_frontend_if_needed():
    if not (DIST_DIR / "index.html").exists():
        print("Frontend production build not found. Building now...")
        cmd = ["node", str(FRONTEND_DIR / "node_modules" / "vite" / "bin" / "vite.js"), "build"]
        subprocess.run(cmd, cwd=str(FRONTEND_DIR), check=True)
        print("Frontend build complete.")

def main():
    build_frontend_if_needed()
    port = int(os.environ.get("PORT", 8001))
    host = os.environ.get("HOST", "0.0.0.0")

    print(f"===========================================================")
    print(f" Nova Cyber Spark™ — Network Traffic Investigation Platform")
    print(f" Founder & Architect: Pranay Kumar Mallem")
    print(f" All Patents & Intellectual Property Rights Reserved")
    print(f" Unified Server running at http://localhost:{port}")
    print(f" API Docs: http://localhost:{port}/api/docs")
    print(f"===========================================================")

    import uvicorn
    # Add backend directory to sys.path
    if str(BACKEND_DIR) not in sys.path:
        sys.path.insert(0, str(BACKEND_DIR))

    uvicorn.run("app.main:app", host=host, port=port, log_level="info", app_dir=str(BACKEND_DIR))

if __name__ == "__main__":
    main()
