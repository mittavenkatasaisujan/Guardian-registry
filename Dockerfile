FROM python:3.13-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 GR_DB=/data/guardian_registry.db

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY guardian_registry ./guardian_registry
RUN useradd --system --uid 10001 app && mkdir /data && chown app /data
USER app
VOLUME ["/data"]
EXPOSE 8000

# Set GR_ENV=production plus GR_PEPPER, GR_DATA_KEY, GR_ADMIN_TOKEN (and GR_SMS_URL/GR_SMS_TOKEN) at run time.
CMD ["uvicorn", "guardian_registry.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
