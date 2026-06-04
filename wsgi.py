"""
wsgi.py — Gunicorn-compatible entry point for the CRM SaaS backend.
"""
import os
import sys
import threading
from server import app as application, load_env, init_db, auth_secret, refresh_secret, validate_supabase_url, followup_scheduler_loop, app_log

load_env()

# ── 1. Enforce JWT secrets ─────────────────────────────────────────────────
try:
    auth_secret()
    refresh_secret()
except RuntimeError as e:
    app_log(str(e), level=50)
    app_log(
        "ACTION REQUIRED: Set JWT_ACCESS_SECRET and JWT_REFRESH_SECRET in "
        "Render → Service → Environment Variables. "
        "Generate values with: python3 -c \"import secrets; print(secrets.token_hex(32))\"",
        level=50
    )
    sys.exit(1)

# ── 2. Validate database connectivity ─────────────────────────────────────
if not validate_supabase_url():
    app_log(
        "Database validation failed. "
        "Set SUPABASE_DB_URL in Render environment variables. "
        "Format: postgresql://user:pass@host:5432/dbname?sslmode=require",
        level=50
    )
    sys.exit(1)

# ── 3. Initialize database schema ─────────────────────────────────────────
try:
    init_db()
    app_log("Database initialized successfully.")
except Exception as exc:
    app_log(f"Database init failed: {exc}", level=50)
    app_log(
        "If using SQLite on Render, the /app directory is read-only. "
        "Either set SUPABASE_DB_URL (recommended) or set SQLITE_DB_PATH=/tmp/crm.sqlite3",
        level=50
    )
    sys.exit(1)

# ── 4. Start background scheduler ─────────────────────────────────────────
scheduler_thread = threading.Thread(target=followup_scheduler_loop, daemon=True)
scheduler_thread.start()
app_log("Follow-up scheduler started.")

