FROM python:3.13-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app

COPY requirements-runtime.txt .
RUN pip install --no-cache-dir -r requirements-runtime.txt

COPY guardian_registry ./guardian_registry
RUN useradd --system --uid 10001 app && mkdir /data && chown app /data
USER app
VOLUME ["/data"]
# Without GR_DB (or GR_DB_FILE) the database is SQLite in /data.
WORKDIR /data
EXPOSE 8000

# Ready = database reachable and schema current (see /readyz).
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=2).status == 200 else 1)"]

# Configuration comes from the environment, secrets preferably as files (GR_PEPPER_FILE=...).
# Client addresses and certificates are taken from the proxy only if it is in GR_TRUSTED_PROXIES,
# so uvicorn's own proxy-header handling stays off.
CMD ["uvicorn", "guardian_registry.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--timeout-keep-alive", "75"]
