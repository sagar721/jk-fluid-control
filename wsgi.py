"""
wsgi.py — Gunicorn-compatible entry point for the CRM SaaS backend.
"""
import os
import sys
import threading
from server import app as application, load_env, init_db, auth_secret, refresh_secret, validate_supabase_url, followup_scheduler_loop, app_log

load_env()

# Enforce secrets configuration
try:
    auth_secret()
    refresh_secret()
except RuntimeError as e:
    app_log(str(e), level=50)  # CRITICAL level is 50
    sys.exit(1)
    
# Enforce Supabase/Postgres connection validation in production mode
if not validate_supabase_url():
    app_log("Supabase validation failed. Aborting startup.", level=50)
    sys.exit(1)
    
try:
    init_db()
except Exception as exc:
    app_log(f"Database init failed: {exc}", level=50)
    sys.exit(1)

# Start background scheduler thread
scheduler_thread = threading.Thread(target=followup_scheduler_loop, daemon=True)
scheduler_thread.start()
