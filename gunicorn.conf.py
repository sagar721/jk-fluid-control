import multiprocessing
import os

# Server socket
bind = f"0.0.0.0:{os.environ.get('PORT', '8765')}"
backlog = 2048

# Worker processes
# Recommended formula: (2 x num_cores) + 1
workers = int(os.environ.get("GUNICORN_WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = "gthread"
threads = int(os.environ.get("GUNICORN_THREADS", 4))
worker_connections = 1000

# Timeout and Keep-Alive
timeout = 60
keepalive = 2

# Logging
loglevel = "info"
accesslog = "-"
errorlog = "-"

# Process naming
proc_name = "jkcrm_gunicorn"

# Server hooks
def on_starting(server):
    server.log.info("Starting JK Fluid Controls CRM via Gunicorn")

def post_fork(server, worker):
    server.log.info(f"Worker spawned (pid: {worker.pid})")
