# Multi-stage Dockerfile for Network Traffic Investigation & Analysis Platform
# Stage 1: Build Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Production Runtime with Wireshark/TShark
FROM python:3.11-slim
WORKDIR /app

# Install system dependencies & TShark
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r ./backend/requirements.txt

# Copy backend code
COPY backend/ ./backend/

# Copy built frontend assets
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Copy runner script
COPY run_production.py ./

# Create data directories
RUN mkdir -p /app/backend/data/uploads /app/backend/data/reports

ENV PORT=8000
ENV HOST=0.0.0.0
ENV TSHARK_PATH=/usr/bin/tshark

EXPOSE 8000

CMD ["python", "run_production.py"]
