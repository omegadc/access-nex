# syntax=docker/dockerfile:1

# The Python/FastAPI frontend: renders every browser-facing page and proxies
# everything else to the Go backend (see docs/FRONTEND.md). Built from the
# repo root so it can pick up requirements.txt, main.py, and the frontend/
# package in one context:
#
#   docker build -f frontend/Dockerfile -t access-nex-frontend .
#
# docker-compose.yml wires this up alongside the Go backend already built by
# the top-level Dockerfile.

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY frontend/ ./frontend/

# Not secret, just where to find the backend — override per environment
# (docker-compose points this at the access-nex service's Docker DNS name).
ENV ACCESS_NEX_BACKEND_URL=http://access-nex:8080

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
