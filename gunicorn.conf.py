import multiprocessing
import os

# Server socket — Render injects PORT automatically
bind = f"0.0.0.0:{os.environ.get('PORT', '10000')}"
backlog = 2048

# Worker processes
workers = int(os.environ.get("GUNICORN_WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = "gthread"
threads = int(os.environ.get("GUNICORN_THREADS", 4))
worker_connections = 1000

# Timeout — increased for Render cold-start
timeout = 120
keepalive = 5

# Logging
loglevel = "info"
accesslog = "-"
errorlog = "-"

# Process naming
proc_name = "jkcrm_gunicorn"

# FIX: Use /dev/shm (RAM tmpfs) for worker temp files.
# This resolves "Permission denied: /app/.gunicorn" on Render and other
# cloud platforms where the app directory is read-only.
worker_tmp_dir = "/dev/shm"

# No pidfile — Render manages the process lifecycle externally.
pidfile = None

# Server hooks
def on_starting(server):
    server.log.info("Starting JK Fluid Controls CRM via Gunicorn")

def post_fork(server, worker):
    server.log.info(f"Worker spawned (pid: {worker.pid})")
