# Nova Cyber Spark™ — Cloud Deployment & Hosting Guide
**Architect & Founder:** Pranay Kumar Mallem  
**Edition:** v2026.1 Enterprise SOC Edition  

This guide provides step-by-step instructions to deploy and host the **Nova Cyber Spark™ — Network Security Investigation & Monitoring Platform** using free cloud tiers:
- **Backend API & Forensic Engine**: Hosted on [Render](https://render.com) (FastAPI + Python 3.11 / Docker)
- **Frontend SOC Dashboard**: Hosted on [Netlify](https://netlify.com) (React 19 + Vite 8 SPA CDN)
- **Code Repository**: GitHub (`Pranay229/Network-Traffic-Investigation-Analysis-Platform`)

---

## 📋 Architecture & Environment Overview

```
                                  ┌──────────────────────────────┐
                                  │   Netlify Global Edge CDN    │
                                  │  (React 19 + Tailwind v4)    │
                                  │  https://<your-app>.netlify  │
                                  └──────────────┬───────────────┘
                                                 │ HTTPS REST + CORS
                                                 ▼
┌──────────────────────────────┐  ┌──────────────────────────────┐
│  GitHub Remote Repository    ├──┤      Render Cloud Web        │
│  origin/main                 │  │    (FastAPI + SQLite/PG)     │
│  (Automatic CI/CD Pipeline)  │  │  https://<your-api>.render   │
└──────────────────────────────┘  └──────────────────────────────┘
```

---

## 🚀 Part 1: Deploy Backend API to Render

1. Sign up or log in at **[https://dashboard.render.com](https://dashboard.render.com)**.
2. Click **New +** in the top right and select **Web Service**.
3. Under **Connect a repository**, choose GitHub and select your repository:
   `Pranay229/Network-Traffic-Investigation-Analysis-Platform`
4. Configure the Web Service settings:
   - **Name**: `nova-cyber-spark-api` (or your preferred name)
   - **Region**: Choose the closest region (e.g., *Oregon (US West)* or *Frankfurt (EU)*)
   - **Branch**: `main`
   - **Root Directory**: Leave blank (repository root)
   - **Runtime**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type**: `Free`
5. Under **Environment Variables**, add:
   | Key | Value | Description |
   |-----|-------|-------------|
   | `PYTHON_VERSION` | `3.11.9` | Python runtime version |
   | `CORS_ORIGINS` | `*` | Permits API requests from your Netlify domain |
   | `COOKIE_SECURE` | `true` | Enforces HTTPS cookie transmission |
   | `JWT_SECRET_KEY` | *(Click Generate or enter a secure random 32+ character string)* | JWT Signing Secret |
6. Click **Create Web Service**.
7. Wait ~2-3 minutes for the build and deployment to complete.
8. Copy your Render service URL (e.g., `https://nova-cyber-spark-api.onrender.com`).
9. Verify health by opening:  
   `https://nova-cyber-spark-api.onrender.com/api/health`  
   Expected JSON response: `{"status": "ok", "app": "Nova Cyber Spark...", ...}`

---

## 🌐 Part 2: Deploy Frontend to Netlify

1. Sign up or log in at **[https://app.netlify.com](https://app.netlify.com)**.
2. Click **Add new site** > **Import an existing project**.
3. Choose **GitHub** as your Git provider and authorize Netlify.
4. Select `Pranay229/Network-Traffic-Investigation-Analysis-Platform`.
5. Netlify will automatically detect the configuration from `netlify.toml`:
   - **Base directory**: `frontend`
   - **Build command**: `npm run build`
   - **Publish directory**: `dist`
6. Click **Environment variables** > **Add a variable**:
   | Key | Value |
   |-----|-------|
   | `VITE_API_URL` | `https://<your-render-service-name>.onrender.com` |
   *(Replace with your actual Render URL from Part 1, without trailing slash)*
7. Click **Deploy nova-cyber-spark** (or **Deploy site**).
8. Netlify will install dependencies, build the React 19 bundle, and deploy to their global CDN in under 1 minute.
9. Click your Netlify URL (e.g., `https://nova-cyber-spark.netlify.app`) to open the live platform.

---

## 🐳 Optional Alternative: Deploy All-in-One via Docker

If you want Wireshark/TShark pre-installed on Linux in the cloud:
1. In Render, select **Runtime: Docker** (using the multi-stage `Dockerfile` in the repository).
2. The Docker container builds the frontend SPA, installs TShark/libpcap, and runs the unified server on `$PORT`.
3. You can access both the SPA frontend and REST backend from a single Render URL!

---

## 💻 Local Production Hosting (Self-Hosted)

To host the entire platform directly on your local machine or internal network:
```powershell
cd "d:\Nova Project's 2026\Network Traffic Investigation & Analysis Platform\network-traffic-investigation"
python run_production.py
```
- **Platform URL**: `http://localhost:8001`
- **Interactive Swagger Docs**: `http://localhost:8001/api/docs`
- **LAN Access**: Replace `localhost` with your machine's local IP (e.g. `http://192.168.1.50:8001`).
