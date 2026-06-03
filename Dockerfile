# Use official lightweight Python image
FROM python:3.11-slim as builder

# Set build-time env variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies needed for compiling python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Final runner stage
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder /install /usr/local

# Create non-root user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -d /app -s /bin/bash appuser

# Copy application files
COPY --chown=appuser:appgroup . .

# Ensure app has permissions to write SQLite database locally if fallback is active
RUN touch crm.sqlite3 && chown appuser:appgroup crm.sqlite3

USER appuser

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:8765/api/health || exit 1

CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:application"]
