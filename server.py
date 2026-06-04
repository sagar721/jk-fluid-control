#!/usr/bin/env python3
import json
import base64
import bcrypt
import hashlib
import hmac
import mimetypes
import os
import secrets
import ssl
import smtplib
import sqlite3
import sys
import re
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import logging
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None

try:
    import certifi
except ImportError:
    certifi = None

# Custom JSON Logging Formatter
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            "timestamp": record.created,
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name
        }
        if record.exc_info:
            log_data["stack_trace"] = self.formatException(record.exc_info)
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)
        return json.dumps(log_data)

logger = logging.getLogger("jkcrm")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(JSONFormatter())
logger.addHandler(ch)

def app_log(message, level=logging.INFO, **fields):
    extra = {"extra_fields": fields}
    logger.log(level, message, extra=extra)

def log_structured(action, user_id, duration_ms, status_code, extra=None):
    log_data = {
        "action": action,
        "user_id": user_id,
        "duration_ms": duration_ms,
        "status_code": status_code,
        **(extra or {})
    }
    app_log(f"Structured log: {action}", **log_data)

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"

# FIX: On Render (and other cloud platforms), /app is read-only.
# Use SQLITE_DB_PATH env var for explicit override, or auto-detect Render
# via the RENDER env var (automatically set by Render) and use /tmp.
def _resolve_db_path() -> Path:
    explicit = os.environ.get("SQLITE_DB_PATH", "").strip()
    if explicit:
        return Path(explicit)
    # Render sets RENDER=true; Fly.io sets FLY_APP_NAME; Heroku sets DYNO
    if os.environ.get("RENDER") or os.environ.get("FLY_APP_NAME") or os.environ.get("DYNO"):
        return Path("/tmp/crm.sqlite3")
    return ROOT / "crm.sqlite3"

DB_PATH = _resolve_db_path()
ACTIVE_DB_ENGINE = None
REFRESH_SESSIONS = {}
AI_CACHE = {}
AI_INFLIGHT = set()
AI_RATE_LIMIT = {}
AI_LOCK = threading.Lock()
STATE_LOCK = threading.Lock()
REQUEST_RATE_LIMIT = {}
REQUEST_RATE_LOCK = threading.Lock()

LOGIN_LIMITS = {}
GENERATE_LIMITS = {}
RATE_LIMIT_LOCK = threading.Lock()

def check_rate_limit(ip, limits_dict, max_requests, window_seconds):
    now_ts = time.time()
    with RATE_LIMIT_LOCK:
        history = limits_dict.get(ip, [])
        history = [t for t in history if now_ts - t < window_seconds]
        if len(history) >= max_requests:
            limits_dict[ip] = history
            return False
        history.append(now_ts)
        limits_dict[ip] = history
        return True

def clear_login_limit(ip):
    with RATE_LIMIT_LOCK:
        if ip in LOGIN_LIMITS:
            del LOGIN_LIMITS[ip]

# Config Functions
def preferred_db_engine():
    engine = str(os.environ.get("DB_ENGINE", "postgres")).strip().lower()
    return "postgres" if engine == "postgres" else "sqlite"

def db_engine():
    global ACTIVE_DB_ENGINE
    if ACTIVE_DB_ENGINE:
        return ACTIVE_DB_ENGINE
    if preferred_db_engine() == "postgres" and psycopg is not None:
        url = os.environ.get("SUPABASE_DB_URL") or os.environ.get("DATABASE_URL")
        if url:
            ACTIVE_DB_ENGINE = "postgres"
            return "postgres"
    ACTIVE_DB_ENGINE = "sqlite"
    return "sqlite"

def auto_fallback_enabled():
    return str(os.environ.get("AUTO_FALLBACK_SQLITE", "true")).strip().lower() in ("1", "true", "yes", "on")

def database_label():
    engine = db_engine()
    if engine == "postgres":
        return "PostgreSQL (Supabase)"
    if auto_fallback_enabled() and preferred_db_engine() == "postgres":
        return "SQLite fallback (Postgres offline)"
    return "SQLite local"

def db_available():
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
        return True
    except Exception:
        return False

def _mask_supabase_url(url: str) -> str:
    if "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    if "@" not in rest:
        return url
    auth, host = rest.split("@", 1)
    if ":" in auth:
        user, _ = auth.split(":", 1)
        masked_auth = f"{user}:***"
    else:
        masked_auth = auth
    return f"{scheme}://{masked_auth}@{host}"

def validate_supabase_url() -> bool:
    url = os.getenv("SUPABASE_DB_URL") or os.getenv("DATABASE_URL")
    if not url:
        if auto_fallback_enabled() or preferred_db_engine() == "sqlite":
            app_log("Supabase URL missing, falling back to local SQLite database.")
            return True
        app_log("Supabase validation failed: SUPABASE_DB_URL is missing from environment.", level=logging.WARNING)
        return False

    delays = [2, 4, 8]
    for attempt, delay in enumerate(delays, start=1):
        try:
            with psycopg.connect(url, connect_timeout=5) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
            app_log("Supabase connection verified")
            return True
        except Exception as exc:
            masked = _mask_supabase_url(url)
            app_log(
                "Supabase connection test failed",
                attempt=attempt,
                url=masked,
                error=str(exc),
                level=logging.WARNING
            )
            if attempt < len(delays):
                time.sleep(delay)
    return False

def q(sql):
    if db_engine() == "postgres":
        return sql.replace("?", "%s")
    return sql

def load_env():
    env_path = ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

def supabase_url():
    return str(os.environ.get("NEXT_PUBLIC_SUPABASE_URL") or os.environ.get("VITE_SUPABASE_URL") or "").strip()

def supabase_anon_key():
    return str(os.environ.get("NEXT_PUBLIC_SUPABASE_ANON_KEY") or os.environ.get("VITE_SUPABASE_ANON_KEY") or "").strip()

def supabase_auth_ready():
    url = supabase_url()
    key = supabase_anon_key()
    return bool(url and key and key != "YOUR_ANON_KEY")

def build_account_profile(state, email, auth_user=None):
    users = state.get("users", []) if isinstance(state, dict) else []
    local_account = next((item for item in users if item.get("email", "").lower() == email.lower()), {})
    auth_user = auth_user or {}
    user_metadata = auth_user.get("user_metadata") or {}
    app_metadata = auth_user.get("app_metadata") or {}
    role = str(user_metadata.get("role") or app_metadata.get("role") or local_account.get("role") or "MANAGER").upper()
    if role not in ("ADMIN", "MANAGER", "SALES", "VIEWER"):
        role = "MANAGER"
    name = user_metadata.get("name") or user_metadata.get("full_name") or local_account.get("name") or email.split("@", 1)[0].replace(".", " ").title()
    return {
        "id": auth_user.get("id") or local_account.get("id") or email,
        "name": name,
        "email": email,
        "role": role,
        "phone": user_metadata.get("phone") or local_account.get("phone", ""),
        "active": True,
    }

def supabase_password_login(email, password):
    body = json.dumps({"email": email, "password": password}).encode("utf-8")
    request_obj = urllib.request.Request(
        f"{supabase_url()}/auth/v1/token?grant_type=password",
        data=body,
        headers={
            "apikey": supabase_anon_key(),
            "authorization": f"Bearer {supabase_anon_key()}",
            "content-type": "application/json",
        },
        method="POST",
    )
    ssl_context = None
    if certifi:
        ssl_context = ssl.create_default_context(cafile=certifi.where())
    try:
        with urllib.request.urlopen(request_obj, timeout=8, context=ssl_context) as response:
            return json.loads(response.read().decode("utf-8")), None, 200
    except urllib.error.HTTPError as exc:
        detail = "Invalid email or password"
        try:
            payload = json.loads(exc.read().decode("utf-8"))
            detail = payload.get("msg") or payload.get("error_description") or payload.get("error") or detail
        except Exception:
            pass
        return None, detail, exc.code
    except Exception as exc:
        app_log("Supabase auth failed", error=str(exc))
        return None, "Supabase login is unavailable right now.", 503

def auth_secret():
    secret = os.environ.get("JWT_ACCESS_SECRET")
    if not secret:
        raise RuntimeError("JWT_ACCESS_SECRET is missing from environment")
    return secret

def refresh_secret():
    secret = os.environ.get("JWT_REFRESH_SECRET")
    if not secret:
        raise RuntimeError("JWT_REFRESH_SECRET is missing from environment")
    return secret

def b64url_encode(value):
    return base64.urlsafe_b64encode(value).decode("utf-8").rstrip("=")

def b64url_decode(value):
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8"))

def sign_token(payload, secret):
    body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = b64url_encode(hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).digest())
    return f"{body}.{signature}"

def verify_token(token, secret):
    if not token or "." not in token:
        return None
    body, signature = token.split(".", 1)
    expected = b64url_encode(hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        payload = json.loads(b64url_decode(body).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload

def issue_access_token(user):
    now_ts = int(time.time())
    payload = {
        "sub": user.get("id"),
        "email": user.get("email"),
        "role": user.get("role"),
        "name": user.get("name"),
        "iat": now_ts,
        "exp": now_ts + int(os.environ.get("ACCESS_TOKEN_TTL_SECONDS", "900")),
    }
    return sign_token(payload, auth_secret())

def issue_refresh_token(user):
    now_ts = int(time.time())
    jti = secrets.token_hex(16)
    payload = {
        "sub": user.get("id"),
        "email": user.get("email"),
        "role": user.get("role"),
        "name": user.get("name"),
        "jti": jti,
        "iat": now_ts,
        "exp": now_ts + int(os.environ.get("REFRESH_TOKEN_TTL_SECONDS", "604800")),
    }
    token = sign_token(payload, refresh_secret())
    REFRESH_SESSIONS[token] = {"email": user.get("email"), "jti": jti, "exp": payload["exp"]}
    return token

def parse_bearer(headers):
    auth = str(headers.get("Authorization", "")).strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""

# Database connection manager class to wrap SQLite and psycopg
class DbConn:
    def __init__(self, engine, url_or_path):
        self.engine = engine
        self.url_or_path = url_or_path
        self.conn = None

    def __enter__(self):
        if self.engine == "postgres":
            if psycopg is None:
                raise ImportError("psycopg is not installed")
            self.conn = psycopg.connect(self.url_or_path, row_factory=dict_row)
        else:
            self.conn = sqlite3.connect(self.url_or_path, timeout=15)
            self.conn.row_factory = sqlite3.Row
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            if exc_type is not None:
                try:
                    self.conn.rollback()
                except Exception:
                    pass
            else:
                try:
                    self.conn.commit()
                except Exception:
                    pass
            self.conn.close()

    def execute(self, sql, params=None):
        cur = self.conn.cursor()
        if params is not None:
            cur.execute(sql, params)
        else:
            cur.execute(sql)
        return cur

    def commit(self):
        self.conn.commit()

    def cursor(self):
        return self.conn.cursor()

def db():
    engine = db_engine()
    if engine == "postgres":
        url = os.environ.get("SUPABASE_DB_URL") or os.environ.get("DATABASE_URL")
        return DbConn("postgres", url)
    return DbConn("sqlite", str(DB_PATH))

def init_db():
    with db() as connection:
        # Check if information schema check is possible on Postgres
        if db_engine() == "postgres":
            try:
                cur = connection.cursor()
                cur.execute("SELECT data_type FROM information_schema.columns WHERE table_name = 'companies' AND column_name = 'id'")
                row = cur.fetchone()
                if row and row[0].lower() == 'uuid':
                    app_log("Altering / dropping UUID-based tables for compatible TEXT IDs", level=logging.WARNING)
                    connection.execute("DROP TABLE IF EXISTS orders CASCADE;")
                    connection.execute("DROP TABLE IF EXISTS quotations CASCADE;")
                    connection.execute("DROP TABLE IF EXISTS inquiries CASCADE;")
                    connection.execute("DROP TABLE IF EXISTS contacts CASCADE;")
                    connection.execute("DROP TABLE IF EXISTS companies CASCADE;")
                    connection.execute("DROP TABLE IF EXISTS activities CASCADE;")
                    connection.commit()
            except Exception as e:
                app_log("Error during Postgres column type checking", error=str(e), level=logging.ERROR)
        else:
            try:
                cur = connection.cursor()
                cur.execute("PRAGMA table_info(activities)")
                columns = [row[1] for row in cur.fetchall()]
                if columns and "lead_id" in columns:
                    app_log("Dropping old SQLite activities table to recreate it with the correct schema", level=logging.WARNING)
                    connection.execute("DROP TABLE IF EXISTS activities;")
                    connection.commit()
            except Exception as e:
                app_log("Error during SQLite activities schema checking", error=str(e), level=logging.ERROR)

        # Core operational tables
        connection.execute(
            """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            role TEXT NOT NULL DEFAULT 'MANAGER',
            password_hash TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """
        )
        connection.execute(
            """
        CREATE TABLE IF NOT EXISTS crm_state (
            id TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
        )
        connection.execute(
            """
        CREATE TABLE IF NOT EXISTS ai_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT if sqlite else SERIAL PRIMARY KEY,
            kind TEXT NOT NULL,
            prompt TEXT NOT NULL,
            response TEXT NOT NULL,
            provider TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""".replace("INTEGER PRIMARY KEY AUTOINCREMENT if sqlite else SERIAL PRIMARY KEY", "SERIAL PRIMARY KEY" if db_engine() == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT")
        )
        connection.execute(
            """
        CREATE TABLE IF NOT EXISTS auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT if sqlite else SERIAL PRIMARY KEY,
            email TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""".replace("INTEGER PRIMARY KEY AUTOINCREMENT if sqlite else SERIAL PRIMARY KEY", "SERIAL PRIMARY KEY" if db_engine() == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT")
        )
        connection.execute(
            """
        CREATE TABLE IF NOT EXISTS communication_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT if sqlite else SERIAL PRIMARY KEY,
            channel TEXT NOT NULL,
            direction TEXT NOT NULL,
            recipient TEXT NOT NULL,
            subject TEXT,
            content TEXT NOT NULL,
            status TEXT NOT NULL,
            provider TEXT NOT NULL,
            linked TEXT,
            created_at TEXT NOT NULL
        )""".replace("INTEGER PRIMARY KEY AUTOINCREMENT if sqlite else SERIAL PRIMARY KEY", "SERIAL PRIMARY KEY" if db_engine() == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT")
        )
        connection.execute(
            """
        CREATE TABLE IF NOT EXISTS api_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT if sqlite else SERIAL PRIMARY KEY,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status INTEGER NOT NULL,
            message TEXT,
            created_at TEXT NOT NULL
        )""".replace("INTEGER PRIMARY KEY AUTOINCREMENT if sqlite else SERIAL PRIMARY KEY", "SERIAL PRIMARY KEY" if db_engine() == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT")
        )
        connection.execute(
            """
        CREATE TABLE IF NOT EXISTS lead_followups (
            lead_id TEXT PRIMARY KEY,
            last_contacted TEXT NOT NULL,
            follow_up_due TEXT NOT NULL,
            follow_up_sent INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
        )
        connection.execute(
            """
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT if sqlite else SERIAL PRIMARY KEY,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        )""".replace("INTEGER PRIMARY KEY AUTOINCREMENT if sqlite else SERIAL PRIMARY KEY", "SERIAL PRIMARY KEY" if db_engine() == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT")
        )

        # CRM Relational tables
        connection.execute(
            """
        CREATE TABLE IF NOT EXISTS companies (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            industry TEXT,
            city TEXT,
            state TEXT,
            country TEXT,
            phone TEXT,
            email TEXT,
            website TEXT,
            location TEXT,
            gst TEXT,
            status TEXT NOT NULL DEFAULT 'LEAD',
            size TEXT,
            assigned_to TEXT,
            tags TEXT,
            workspace_id TEXT,
            user_id TEXT NOT NULL,
            version INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
        )
        connection.execute(
            """
        CREATE TABLE IF NOT EXISTS contacts (
            id TEXT PRIMARY KEY,
            company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            first_name TEXT,
            last_name TEXT,
            name TEXT,
            designation TEXT,
            email TEXT NOT NULL,
            phone TEXT,
            whatsapp TEXT,
            is_primary INTEGER DEFAULT 0,
            wa_opt_in INTEGER DEFAULT 1,
            workspace_id TEXT,
            user_id TEXT NOT NULL,
            version INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
        )
        connection.execute(
            """
        CREATE TABLE IF NOT EXISTS inquiries (
            id TEXT PRIMARY KEY,
            no TEXT UNIQUE,
            company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
            assigned_to TEXT,
            status TEXT NOT NULL DEFAULT 'NEW',
            priority TEXT NOT NULL DEFAULT 'MEDIUM',
            source TEXT,
            project_type TEXT,
            budget_min REAL DEFAULT 0,
            budget_max REAL DEFAULT 0,
            required_date TEXT,
            requirements TEXT,
            notes TEXT,
            is_locked INTEGER DEFAULT 0,
            products TEXT,
            workspace_id TEXT,
            user_id TEXT NOT NULL,
            version INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
        )
        connection.execute(
            """
        CREATE TABLE IF NOT EXISTS quotations (
            id TEXT PRIMARY KEY,
            no TEXT UNIQUE,
            inquiry_id TEXT REFERENCES inquiries(id) ON DELETE SET NULL,
            company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            status TEXT NOT NULL DEFAULT 'DRAFT',
            valid_until TEXT,
            discount REAL DEFAULT 0,
            payment_terms TEXT,
            sent_at TEXT,
            products TEXT,
            total_amount REAL DEFAULT 0,
            workspace_id TEXT,
            user_id TEXT NOT NULL,
            version INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
        )
        connection.execute(
            """
        CREATE TABLE IF NOT EXISTS orders (
            id TEXT PRIMARY KEY,
            no TEXT UNIQUE,
            quotation_id TEXT UNIQUE REFERENCES quotations(id) ON DELETE CASCADE,
            company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            po TEXT,
            status TEXT NOT NULL DEFAULT 'CONFIRMED',
            payment TEXT NOT NULL DEFAULT 'PENDING',
            courier TEXT,
            tracking TEXT,
            dispatch_date TEXT,
            expected_delivery TEXT,
            products TEXT,
            value REAL DEFAULT 0,
            amount REAL DEFAULT 0,
            workspace_id TEXT,
            user_id TEXT NOT NULL,
            version INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
        )
        connection.execute(
            """
        CREATE TABLE IF NOT EXISTS activities (
            id TEXT PRIMARY KEY,
            type TEXT,
            title TEXT,
            company_id TEXT,
            contact_id TEXT,
            inquiry_id TEXT,
            owner TEXT,
            due TEXT,
            outcome TEXT,
            done INTEGER DEFAULT 0,
            workspace_id TEXT,
            user_id TEXT NOT NULL,
            version INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
        )
        connection.commit()

        # Indexes for lookup performance
        try:
            connection.execute("CREATE INDEX IF NOT EXISTS idx_companies_user_id ON companies(user_id);")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_companies_workspace_id ON companies(workspace_id);")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_contacts_company_id ON contacts(company_id);")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_inquiries_company_id ON inquiries(company_id);")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_quotations_inquiry_id ON quotations(inquiry_id);")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_orders_quotation_id ON orders(quotation_id);")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_activities_company_id ON activities(company_id);")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_activities_inquiry_id ON activities(inquiry_id);")
            connection.commit()
        except Exception as e:
            app_log("Index creation warning", error=str(e), level=logging.WARNING)

    seed_demo_users()

def seed_demo_users():
    demo_users = [
        {"id": "u-admin", "email": "admin@jkfluidcontrols.com", "name": "System Admin", "role": "ADMIN", "password": "demo123"},
        {"id": "u-manager", "email": "manager@jkfluidcontrols.com", "name": "Sales Manager", "role": "MANAGER", "password": "demo123"},
        {"id": "u-sales", "email": "sales@jkfluidcontrols.com", "name": "Sales Executive", "role": "SALES", "password": "demo123"},
        {"id": "u-viewer", "email": "viewer@jkfluidcontrols.com", "name": "Auditor", "role": "VIEWER", "password": "demo123"},
    ]
    with db() as connection:
        for u in demo_users:
            cur = connection.execute(q("SELECT id FROM users WHERE email = ?"), (u["email"],))
            if not cur.fetchone():
                pwd_hash = bcrypt.hashpw(u["password"].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                connection.execute(
                    q("INSERT INTO users (id, email, name, role, password_hash, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"),
                    (u["id"], u["email"], u["name"], u["role"], pwd_hash, 1, now())
                )
        connection.commit()

def now():
    return datetime.utcnow().isoformat() + "Z"

def today_iso():
    return datetime.utcnow().date().isoformat()

def iso_now():
    return now()

def static_root():
    dist_dir = ROOT / "dist"
    return dist_dir if dist_dir.exists() else ROOT

def parse_datetime(value):
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(value).strip(), fmt)
        except ValueError:
            continue
    return None

def elapsed_hours_since(value):
    dt = parse_datetime(value)
    if not dt:
        return 0.0
    return (datetime.utcnow() - dt).total_seconds() / 3600.0

def load_state(state_id="default"):
    with STATE_LOCK:
        with db() as connection:
            row = connection.execute(q("SELECT payload FROM crm_state WHERE id = ?"), (state_id,)).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["payload"])
    except (json.JSONDecodeError, TypeError):
        return None

def save_state(payload, state_id="default"):
    payload_str = json.dumps(payload)
    with STATE_LOCK:
        with db() as connection:
            connection.execute(
                q(
                    """
                INSERT INTO crm_state (id, payload, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at
                """
                ) if db_engine() == "postgres" else q(
                    """
                INSERT OR REPLACE INTO crm_state (id, payload, updated_at)
                VALUES (?, ?, ?)
                """
                ),
                (state_id, payload_str, now()),
            )
            connection.commit()

def log_ai(kind, prompt, response, provider):
    try:
        with db() as conn:
            conn.execute(
                q("INSERT INTO ai_logs (kind, prompt, response, provider, created_at) VALUES (?, ?, ?, ?, ?)"),
                (kind, prompt, response, provider, now())
            )
            conn.commit()
    except Exception as exc:
        app_log("AI logging failed", error=str(exc), level=logging.ERROR)

def log_auth(email, status):
    try:
        with db() as conn:
            conn.execute(
                q("INSERT INTO auth_events (email, status, created_at) VALUES (?, ?, ?)"),
                (email, status, now())
            )
            conn.commit()
    except Exception as exc:
        app_log("Auth logging failed", error=str(exc), level=logging.ERROR)

def log_activity_event(user_id, action, entity_type, entity_id, details=None):
    try:
        detail_str = json.dumps(details) if details else ""
        with db() as conn:
            conn.execute(
                q("INSERT INTO activity_logs (user_id, action, entity_type, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)"),
                (user_id, action, entity_type, entity_id, detail_str, now())
            )
            conn.commit()
    except Exception as exc:
        app_log("Activity logging failed", error=str(exc), level=logging.ERROR)

def log_communication(channel, direction, recipient, subject, content, status, provider, linked=""):
    try:
        with db() as conn:
            conn.execute(
                q("INSERT INTO communication_logs (channel, direction, recipient, subject, content, status, provider, linked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"),
                (channel, direction, recipient, subject, content, status, provider, linked, now())
            )
            conn.commit()
    except Exception as exc:
        app_log("Communication logging failed", error=str(exc), level=logging.ERROR)

def communication_logs(limit=50):
    try:
        with db() as conn:
            rows = conn.execute(q("SELECT channel, direction, recipient, subject, content, status, provider, linked, created_at FROM communication_logs ORDER BY id DESC LIMIT ?"), (limit,)).fetchall()
        return [dict(row) for row in rows]
    except Exception:
        return []

def api_logs(limit=100):
    try:
        with db() as conn:
            rows = conn.execute(q("SELECT method, path, status, message, created_at FROM api_logs ORDER BY id DESC LIMIT ?"), (limit,)).fetchall()
        return [dict(row) for row in rows]
    except Exception:
        return []

def log_api(method, path, status, message=""):
    try:
        with db() as conn:
            conn.execute(
                q("INSERT INTO api_logs (method, path, status, message, created_at) VALUES (?, ?, ?, ?, ?)"),
                (method, path, int(status), str(message)[:350], now())
            )
            conn.commit()
    except Exception:
        pass

# Snake / Camel mapping helpers
def to_camel_case(record, table):
    if not record:
        return {}
    res = {}
    for k, v in record.items():
        if k in ("tags", "products", "requirements") and isinstance(v, str):
            try:
                v = json.loads(v)
            except Exception:
                v = []
        if k in ("is_primary", "wa_opt_in", "is_locked", "done"):
            v = bool(v)
            
        if k == "assigned_to":
            res["assignedTo"] = v
        elif k == "company_id":
            res["companyId"] = v
        elif k == "contact_id":
            res["contactId"] = v
        elif k == "first_name":
            res["first"] = v
        elif k == "last_name":
            res["last"] = v
        elif k == "wa_opt_in":
            res["waOptIn"] = v
        elif k == "is_primary":
            res["primary"] = v
        elif k == "project_type":
            res["projectType"] = v
        elif k == "budget_min":
            res["budgetMin"] = v
        elif k == "budget_max":
            res["budgetMax"] = v
        elif k == "required_date":
            res["requiredDate"] = v
        elif k == "is_locked":
            res["isLocked"] = v
        elif k == "inquiry_id":
            res["inquiryId"] = v
        elif k == "valid_until":
            res["validUntil"] = v
        elif k == "payment_terms":
            res["paymentTerms"] = v
        elif k == "sent_at":
            res["sentAt"] = v
        elif k == "total_amount":
            res["totalAmount"] = v
        elif k == "quotation_id":
            res["quotationId"] = v
        elif k == "dispatch_date":
            res["dispatchDate"] = v
        elif k == "expected_delivery":
            res["expectedDelivery"] = v
        elif k == "created_at":
            res["createdAt"] = v
        elif k == "updated_at":
            res["updatedAt"] = v
        else:
            res[k] = v
    return res

def to_snake_case(record):
    if not record:
        return {}
    res = {}
    for k, v in record.items():
        if k in ("tags", "products", "requirements") and not isinstance(v, str):
            v = json.dumps(v)
        if k in ("primary", "waOptIn", "isLocked", "done"):
            v = 1 if v else 0
            
        if k == "assignedTo":
            res["assigned_to"] = v
        elif k == "companyId":
            res["company_id"] = v
        elif k == "contactId":
            res["contact_id"] = v
        elif k == "first":
            res["first_name"] = v
        elif k == "last":
            res["last_name"] = v
        elif k == "waOptIn":
            res["wa_opt_in"] = v
        elif k == "primary":
            res["is_primary"] = v
        elif k == "projectType":
            res["project_type"] = v
        elif k == "budgetMin":
            res["budget_min"] = v
        elif k == "budgetMax":
            res["budget_max"] = v
        elif k == "requiredDate":
            res["required_date"] = v
        elif k == "isLocked":
            res["is_locked"] = v
        elif k == "inquiryId":
            res["inquiry_id"] = v
        elif k == "validUntil":
            res["valid_until"] = v
        elif k == "paymentTerms":
            res["payment_terms"] = v
        elif k == "sentAt":
            res["sent_at"] = v
        elif k == "totalAmount":
            res["total_amount"] = v
        elif k == "quotationId":
            res["quotation_id"] = v
        elif k == "dispatchDate":
            res["dispatch_date"] = v
        elif k == "expectedDelivery":
            res["expected_delivery"] = v
        elif k == "createdAt":
            res["created_at"] = v
        elif k == "updatedAt":
            res["updated_at"] = v
        else:
            res[k] = v
    return res

# Scoped DB collections
def load_relational_collection(table_name, user):
    w_id = user.get("workspace_id")
    u_id = user.get("sub")
    query = f"SELECT * FROM {table_name} WHERE "
    params = []
    if w_id:
        query += "workspace_id = ?"
        params.append(w_id)
    else:
        query += "user_id = ?"
        params.append(u_id)
        
    # Apply SALES role filtering
    if user.get("role") == "SALES":
        if table_name == "companies":
            query += " AND (assigned_to = ? OR user_id = ?)"
            params.extend([user.get("email"), u_id])
        elif table_name == "contacts":
            query += " AND company_id IN (SELECT id FROM companies WHERE assigned_to = ? OR user_id = ?)"
            params.extend([user.get("email"), u_id])
        elif table_name == "inquiries":
            query += " AND (assigned_to = ? OR user_id = ?)"
            params.extend([user.get("email"), u_id])
        elif table_name == "quotations":
            query += " AND (company_id IN (SELECT id FROM companies WHERE assigned_to = ? OR user_id = ?) OR user_id = ?)"
            params.extend([user.get("email"), u_id, u_id])
        elif table_name == "orders":
            query += " AND (company_id IN (SELECT id FROM companies WHERE assigned_to = ? OR user_id = ?) OR user_id = ?)"
            params.extend([user.get("email"), u_id, u_id])
        elif table_name == "activities":
            query += " AND (owner = ? OR user_id = ?)"
            params.extend([user.get("email"), u_id])

    with db() as conn:
        rows = conn.execute(q(query), tuple(params)).fetchall()
    return [dict(row) for row in rows]

def check_sales_access(table_name, record_id, user):
    if user["role"] == "SALES":
        with db() as conn:
            row = conn.execute(q(f"SELECT * FROM {table_name} WHERE id = ?"), (record_id,)).fetchone()
        if row:
            row_dict = dict(row)
            assigned_to = row_dict.get("assigned_to") or row_dict.get("owner")
            creator = row_dict.get("user_id")
            if assigned_to != user["email"] and creator != user["sub"]:
                return False
    return True

# DB CRUD helpers
def insert_db_row(table, record, user):
    if user["role"] == "VIEWER":
        raise PermissionError("Viewer role cannot modify state")
        
    row = to_snake_case(record)
    if "id" not in row or not row["id"]:
        prefix_map = {
            "companies": "c",
            "contacts": "p",
            "inquiries": "i",
            "quotations": "q",
            "orders": "o",
            "activities": "a"
        }
        row["id"] = next_id(prefix_map.get(table, "ent"))
        
    row["user_id"] = user["sub"]
    row["workspace_id"] = user.get("workspace_id")
    row["version"] = 1
    row["created_at"] = now()
    row["updated_at"] = now()
    
    columns = list(row.keys())
    placeholders = ["?"] * len(columns)
    query = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"
    
    with db() as conn:
        conn.execute(q(query), tuple(row[col] for col in columns))
        conn.commit()
        
    log_activity_event(user["sub"], "CREATE", table[:-1], row["id"], {"name": row.get("name") or row.get("no")})
    return to_camel_case(row, table)

def update_db_row(table, record_id, record, user):
    if user["role"] == "VIEWER":
        raise PermissionError("Viewer role cannot modify state")
        
    if not check_sales_access(table, record_id, user):
        raise PermissionError("Sales role does not have access to this record")
        
    with db() as conn:
        cur_row = conn.execute(q(f"SELECT * FROM {table} WHERE id = ?"), (record_id,)).fetchone()
    if not cur_row:
        raise ValueError(f"Record {record_id} not found in {table}")
        
    cur_row = dict(cur_row)
    
    # Concurrency check
    incoming_version = int(record.get("version") or 0)
    current_version = int(cur_row.get("version") or 0)
    if incoming_version and current_version and incoming_version < current_version:
        raise ConflictError(f"Record {record_id} was updated in another tab/request.")
        
    updates = to_snake_case(record)
    updates.pop("id", None)
    updates.pop("user_id", None)
    updates.pop("workspace_id", None)
    updates["updated_at"] = now()
    updates["version"] = current_version + 1
    
    set_clauses = [f"{col} = ?" for col in updates.keys()]
    query = f"UPDATE {table} SET {', '.join(set_clauses)} WHERE id = ?"
    params = list(updates.values()) + [record_id]
    
    with db() as conn:
        conn.execute(q(query), tuple(params))
        conn.commit()
        
    with db() as conn:
        updated_row = conn.execute(q(f"SELECT * FROM {table} WHERE id = ?"), (record_id,)).fetchone()
        
    log_activity_event(user["sub"], "UPDATE", table[:-1], record_id, {"name": updates.get("name") or updates.get("no")})
    return to_camel_case(dict(updated_row), table)

def delete_db_row(table, record_id, user):
    if user["role"] == "VIEWER":
        raise PermissionError("Viewer role cannot modify state")
        
    if not check_sales_access(table, record_id, user):
        raise PermissionError("Sales role does not have access to this record")
        
    query = f"DELETE FROM {table} WHERE id = ?"
    with db() as conn:
        conn.execute(q(query), (record_id,))
        conn.commit()
        
    log_activity_event(user["sub"], "DELETE", table[:-1], record_id)
    return True

# Merge and sanitize helpers
def load_user_state(user):
    state_id = state_scope_for_user(user)
    scoped = load_state(state_id)
    if scoped is None:
        scoped = default_state_payload()
        
    # Merge relational database entries
    companies = load_relational_collection("companies", user)
    contacts = load_relational_collection("contacts", user)
    inquiries = load_relational_collection("inquiries", user)
    quotations = load_relational_collection("quotations", user)
    orders = load_relational_collection("orders", user)
    activities = load_relational_collection("activities", user)
    
    scoped["companies"] = [to_camel_case(item, "companies") for item in companies]
    scoped["contacts"] = [to_camel_case(item, "contacts") for item in contacts]
    scoped["inquiries"] = [to_camel_case(item, "inquiries") for item in inquiries]
    scoped["quotations"] = [to_camel_case(item, "quotations") for item in quotations]
    scoped["orders"] = [to_camel_case(item, "orders") for item in orders]
    scoped["activities"] = [to_camel_case(item, "activities") for item in activities]
    
    return sanitize_crm_state(scoped, user)

def resolve_request_state(user, request_state=None, persist=False):
    current = load_user_state(user)
    merged = merge_state_payload(current, request_state) if isinstance(request_state, dict) else current
    sanitized = sanitize_crm_state(merged, user)
    if persist:
        save_state_payload(sanitized, user)
    return sanitized

def save_state_payload(incoming, user):
    if user["role"] == "VIEWER":
        raise PermissionError("Viewer role cannot modify state")
        
    state_id = state_scope_for_user(user)
    current = load_state(state_id) or default_state_payload()
    
    # 1. Version/Concurrency Validation
    for table in ("companies", "contacts", "inquiries", "quotations", "orders", "activities"):
        incoming_list = incoming.get(table)
        if incoming_list is None:
            continue
        db_items = {item["id"]: item for item in load_relational_collection(table, user)}
        for item in incoming_list:
            if not isinstance(item, dict):
                continue
            item_id = item.get("id")
            if not item_id or item_id not in db_items:
                continue
            db_item = db_items[item_id]
            incoming_version = int(item.get("version") or 0)
            db_version = int(db_item.get("version") or 0)
            if incoming_version and db_version and incoming_version < db_version:
                raise ConflictError(f"{table[:-1].title()} {item_id} was updated in another tab/request.")

    # 2. Enforce locked inquiry checks
    detect_locked_inquiry_changes(current, incoming)
    
    # 3. Perform Upserts
    for table in ("companies", "contacts", "inquiries", "quotations", "orders", "activities"):
        incoming_list = incoming.get(table)
        if incoming_list is None:
            continue
        incoming_ids = set()
        for item in incoming_list:
            if not isinstance(item, dict):
                continue
            item_id = item.get("id")
            if not item_id:
                res = insert_db_row(table, item, user)
                incoming_ids.add(res["id"])
            else:
                with db() as conn:
                    exists = conn.execute(q(f"SELECT id FROM {table} WHERE id = ?"), (item_id,)).fetchone()
                if exists:
                    res = update_db_row(table, item_id, item, user)
                    incoming_ids.add(item_id)
                else:
                    res = insert_db_row(table, item, user)
                    incoming_ids.add(res["id"])
                    
        # 4. Deletions
        db_items = load_relational_collection(table, user)
        for db_item in db_items:
            db_id = db_item["id"]
            if db_id not in incoming_ids:
                if check_sales_access(table, db_id, user):
                    delete_db_row(table, db_id, user)
                    
    # Keep remaining settings in JSON state payload
    json_payload = {}
    for k, v in incoming.items():
        if k not in ("companies", "contacts", "inquiries", "quotations", "orders", "activities", "products", "quoteItems", "pipeline"):
            json_payload[k] = v
            
    payload_str = json.dumps(json_payload)
    with STATE_LOCK:
        with db() as connection:
            connection.execute(
                q(
                    """
                INSERT INTO crm_state (id, payload, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at
                """
                ) if db_engine() == "postgres" else q(
                    """
                INSERT OR REPLACE INTO crm_state (id, payload, updated_at)
                VALUES (?, ?, ?)
                """
                ),
                (state_id, payload_str, now()),
            )
            connection.commit()
            
    return load_user_state(user)

def crm_summary(state):
    companies = state.get("companies", []) if isinstance(state, dict) else []
    inquiries = state.get("inquiries", []) if isinstance(state, dict) else []
    quotations = state.get("quotations", []) if isinstance(state, dict) else []
    orders = state.get("orders", []) if isinstance(state, dict) else []
    activities = state.get("activities", []) if isinstance(state, dict) else []
    pipeline = state.get("pipeline", []) if isinstance(state, dict) else []
    stages = {text_value(stage.get("id"), max_len=80): stage for stage in state.get("stages", []) if isinstance(stage, dict)} if isinstance(state, dict) else {}
    pipeline_value = round(sum(numeric_value(item.get("value"), 0) for item in pipeline), 2)
    quote_value = round(sum(numeric_value(item.get("totalAmount") or item.get("value"), 0) for item in quotations), 2)
    overdue = [item for item in activities if not boolean_value(item.get("done")) and text_value(item.get("due"), max_len=20) <= today_iso()]
    funnel = []
    for stage_id, stage in stages.items():
        deals = [item for item in pipeline if text_value(item.get("stageId"), max_len=80) == stage_id]
        funnel.append(
            {
                "id": stage_id,
                "name": text_value(stage.get("name"), max_len=120),
                "count": len(deals),
                "value": round(sum(numeric_value(item.get("value"), 0) for item in deals), 2),
            }
        )
    return {
        "counts": {
            "companies": len(companies),
            "contacts": len(state.get("contacts", []) if isinstance(state, dict) else []),
            "inquiries": len(inquiries),
            "openInquiries": len([item for item in inquiries if text_value(item.get("status"), max_len=20).upper() not in ("WON", "LOST")]),
            "quotations": len(quotations),
            "orders": len(orders),
            "activities": len(activities),
            "overdueActivities": len(overdue),
        },
        "pipelineValue": pipeline_value,
        "quoteValue": quote_value,
        "overdueActivities": len(overdue),
        "funnel": funnel,
    }

def detect_intent(text):
    prompt_text = str(text or "").lower()
    if "quote" in prompt_text or "pricing" in prompt_text or "cost" in prompt_text:
        return "QUOTE"
    if "order" in prompt_text or "delivery" in prompt_text or "status" in prompt_text or "dispatch" in prompt_text:
        return "ORDER"
    return "GENERAL"

def contact_context(state, contact_id):
    contacts = state.get("contacts", []) if isinstance(state, dict) else []
    contact = next((item for item in contacts if item.get("id") == contact_id), None)
    if not contact:
        return "No contact found."
    company = find_company(state, contact.get("companyId"))
    inquiries = [item for item in state.get("inquiries", []) if item.get("companyId") == company.get("id")]
    quotes = [item for item in state.get("quotations", []) if item.get("companyId") == company.get("id")]
    orders = [item for item in state.get("orders", []) if item.get("companyId") == company.get("id")]
    return (
        f"Contact: {contact.get('name')} ({contact.get('designation') or 'Staff'})\n"
        f"Company: {company.get('name')} ({company.get('industry') or 'Unknown'})\n"
        f"Inquiries for company: {len(inquiries)}\n"
        f"Quotations for company: {len(quotes)}\n"
        f"Orders for company: {len(orders)}"
    )

def fallback_ai(kind, prompt, state):
    if kind == "whatsapp":
        return "Hello from JK Fluid Controls! We have received your query. A sales representative will check and get back to you shortly."
    if kind == "email":
        return "Subject: Verification of Inquiry from JK Fluid Controls\n\nDear Partner,\n\nThank you for reaching out to JK Fluid Controls. We are processing your request. Please find details attached.\n\nBest Regards,\nJK Fluid Controls Team"
    return f"We have noted your request. [Fallback response due to missing OpenAI connection]"

def fallback_followup_message(lead_id):
    return f"Dear customer, we are following up on your inquiry {lead_id} from JK Fluid Controls. Please let us know if you have any updates on your valve and actuator requirements. Regards, Sales Operations Team."

def sanitize_phone(phone):
    cleaned = re.sub(r"[^\d+]", "", str(phone or ""))
    if cleaned.startswith("91") and len(cleaned) == 12 and not cleaned.startswith("+"):
        return f"+{cleaned}"
    if len(cleaned) == 10:
        return f"+91{cleaned}"
    return cleaned

def valid_phone(phone):
    cleaned = sanitize_phone(phone)
    return bool(cleaned and len(cleaned) >= 10)

def create_activity(lead_id, activity_type, status, detail, meta=None):
    try:
        activity = {
            "id": next_id("a"),
            "type": activity_type,
            "title": f"{activity_type} - {status}",
            "company_id": "",
            "contact_id": "",
            "inquiry_id": lead_id,
            "owner": "system",
            "due": today_iso(),
            "outcome": detail,
            "done": 1,
            "workspace_id": "",
            "user_id": "system",
            "version": 1,
            "created_at": now(),
            "updated_at": now()
        }
        with db() as conn:
            row = to_snake_case(activity)
            columns = list(row.keys())
            placeholders = ["?"] * len(columns)
            conn.execute(q(f"INSERT INTO activities ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"), tuple(row[col] for col in columns))
            conn.commit()
    except Exception as exc:
        app_log("Activity creation failed", error=str(exc), level=logging.ERROR)

def get_activities(limit=200):
    try:
        with db() as conn:
            rows = conn.cursor().execute(q("SELECT * FROM activities ORDER BY id DESC LIMIT ?"), (limit,)).fetchall()
        return [to_camel_case(dict(row), "activities") for row in rows]
    except Exception:
        return []

def mark_lead_contacted(lead_id, follow_up_sent=False):
    sent_val = 1 if follow_up_sent else 0
    with db() as connection:
        connection.execute(
            q("UPDATE lead_followups SET follow_up_sent = ?, last_contacted = ?, updated_at = ? WHERE lead_id = ?"),
            (sent_val, now(), now(), lead_id),
        )
        connection.commit()

def mark_followup_sent(lead_id):
    with db() as connection:
        connection.execute(
            q("UPDATE lead_followups SET follow_up_sent = 1, updated_at = ? WHERE lead_id = ?"),
            (now(), lead_id),
        )
        connection.commit()

def pending_followups(limit=100):
    with db() as connection:
        rows = connection.execute(
            q(
                """
            SELECT lead_id, last_contacted, follow_up_due, follow_up_sent
            FROM lead_followups
            WHERE follow_up_sent = 0 AND follow_up_due <= ?
            ORDER BY follow_up_due ASC
            LIMIT ?
            """
            ),
            (now(), limit),
        ).fetchall()
    return [dict(row) for row in rows]

def ai_rate_allowed(user_id):
    user_key = user_id or "anonymous"
    limit = int(os.environ.get("AI_SESSION_LIMIT", "40"))
    window = int(os.environ.get("AI_SESSION_WINDOW_SECONDS", "3600"))
    now_ts = int(time.time())
    with AI_LOCK:
        timestamps = [ts for ts in AI_RATE_LIMIT.get(user_key, []) if now_ts - ts < window]
        if len(timestamps) >= limit:
            AI_RATE_LIMIT[user_key] = timestamps
            return False
        timestamps.append(now_ts)
        AI_RATE_LIMIT[user_key] = timestamps
    return True

def generate_message_safe(lead_id, prompt, state, user_id="", kind="assistant"):
    lead_key = str(lead_id or "general")
    prompt_key = str(prompt or "").strip()
    cache_key = f"{kind}:{lead_key}:{hashlib.sha256(prompt_key.encode('utf-8')).hexdigest()}"
    with AI_LOCK:
        cached = AI_CACHE.get(cache_key)
        if cached:
            return cached["answer"], cached["provider"], True, None
        if cache_key in AI_INFLIGHT:
            fallback = fallback_followup_message(lead_key)
            return fallback, "fallback", False, "duplicate_request"
        AI_INFLIGHT.add(cache_key)
    try:
        if not ai_rate_allowed(user_id):
            fallback = fallback_followup_message(lead_key)
            return fallback, "fallback", False, "rate_limited"
        attempts = 3
        delay = 1.0
        last_error = ""
        for _ in range(attempts):
            try:
                answer, provider = call_openai(kind, prompt_key, state, "")
                if answer:
                    with AI_LOCK:
                        AI_CACHE[cache_key] = {"answer": answer, "provider": provider, "at": now()}
                    return answer, provider, False, None
            except Exception as exc:
                last_error = str(exc)
            time.sleep(delay)
            delay *= 2
        fallback = fallback_followup_message(lead_key)
        return fallback, "fallback", False, last_error or "ai_unavailable"
    finally:
        with AI_LOCK:
            AI_INFLIGHT.discard(cache_key)

def next_id(prefix):
    return f"{prefix}-{int(time.time() * 1000)}"

STATE_COLLECTION_KEYS = (
    "users",
    "companies",
    "contacts",
    "stages",
    "inquiries",
    "products",
    "pipeline",
    "quotations",
    "quoteItems",
    "orders",
    "activities",
    "messages",
    "emails",
    "automations",
    "automationLog",
    "audit",
)
PAGINATED_COLLECTIONS = {
    "companies",
    "contacts",
    "inquiries",
    "pipeline",
    "quotations",
    "orders",
    "activities",
    "messages",
    "emails",
    "automationLog",
    "audit",
}
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

class ValidationError(ValueError):
    pass

class ConflictError(ValueError):
    pass

def json_clone(value):
    return json.loads(json.dumps(value if value is not None else {}))

def state_scope_for_user(user):
    if user.get("workspace_id"):
        return f"workspace:{user['workspace_id']}"
    identifier = str(user.get("sub") or user.get("id") or user.get("email") or "anonymous").strip()
    return f"user:{identifier}"

def merge_state_payload(existing, incoming):
    merged = json_clone(existing if isinstance(existing, dict) else {})
    payload = incoming if isinstance(incoming, dict) else {}
    loaded = payload.get("loadedCollections")
    loaded = loaded if isinstance(loaded, dict) else {}
    for key, value in payload.items():
        if key in ("session", "activePage"):
            continue
        if key in STATE_COLLECTION_KEYS:
            if loaded.get(key) or (key in payload and not loaded):
                merged[key] = json_clone(value if isinstance(value, list) else [])
            continue
        merged[key] = json_clone(value)
    merged["loadedCollections"] = {
        **(merged.get("loadedCollections") if isinstance(merged.get("loadedCollections"), dict) else {}),
        **loaded,
    }
    return merged

def text_value(value, default="", max_len=400):
    text = str(value or default).strip()
    return text[:max_len]

def numeric_value(value, default=0.0):
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return float(default)
    if numeric != numeric:
        return float(default)
    return float(numeric)

def integer_value(value, default=0):
    return int(round(numeric_value(value, default)))

def boolean_value(value):
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    return text in ("1", "true", "yes", "on")

def find_company(state, company_id):
    companies = state.get("companies", []) if isinstance(state, dict) else []
    return next((item for item in companies if item.get("id") == company_id), {})

def find_contact(state, contact_id):
    contacts = state.get("contacts", []) if isinstance(state, dict) else []
    return next((item for item in contacts if item.get("id") == contact_id), {})

def primary_contact_for_company(state, company_id):
    contacts = state.get("contacts", []) if isinstance(state, dict) else []
    company_contacts = [item for item in contacts if item.get("companyId") == company_id]
    if not company_contacts:
        return {}
    primary = next((item for item in company_contacts if boolean_value(item.get("primary"))), None)
    return primary or company_contacts[0]

def next_inquiry_no(state):
    inquiries = state.get("inquiries", []) if isinstance(state, dict) else []
    max_no = 0
    for item in inquiries:
        no_str = str(item.get("no") or "")
        if no_str.startswith("INQ-"):
            try:
                max_no = max(max_no, int(no_str.split("-")[1]))
            except ValueError:
                pass
    return f"INQ-{max_no + 1:04d}"

def next_quotation_no(state):
    quotations = state.get("quotations", []) if isinstance(state, dict) else []
    max_no = 0
    for item in quotations:
        no_str = str(item.get("no") or "")
        if no_str.startswith("QT-"):
            try:
                max_no = max(max_no, int(no_str.split("-")[1]))
            except ValueError:
                pass
    return f"QT-{max_no + 1:04d}"

def next_order_no(state):
    orders = state.get("orders", []) if isinstance(state, dict) else []
    max_no = 0
    for item in orders:
        no_str = str(item.get("no") or "")
        if no_str.startswith("ORD-"):
            try:
                max_no = max(max_no, int(no_str.split("-")[1]))
            except ValueError:
                pass
    return f"ORD-{max_no + 1:04d}"

def sanitize_products(value, item_id=""):
    items = []
    raw_list = value if isinstance(value, list) else []
    for index, raw in enumerate(raw_list):
        if not isinstance(raw, dict):
            continue
        items.append(
            {
                "id": text_value(raw.get("id"), f"{item_id}-p-{index}"),
                "name": text_value(raw.get("name"), "Industrial Valve"),
                "quantity": integer_value(raw.get("quantity"), 1),
                "price": numeric_value(raw.get("price"), 0.0),
                "specification": text_value(raw.get("specification"), max_len=600),
            }
        )
    return items

def append_audit(state, action, entity, user="Automation"):
    state_lists(state)
    state["audit"].append({"id": next_id("log"), "user": user, "action": action, "entity": entity, "at": now()})

def send_email_provider(to_email, subject, content):
    smtp_host = os.environ.get("SMTP_HOST") or os.environ.get("GMAIL_SMTP_HOST")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    smtp_from = os.environ.get("SMTP_FROM") or smtp_user or "sales@jkfluidcontrols.com"
    if not smtp_host or not smtp_user or not smtp_pass:
        return "SIMULATED", "simulated"

    message = EmailMessage()
    message["From"] = smtp_from
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(content)
    port = int(os.environ.get("SMTP_PORT", "587"))
    for attempt in range(2):
        try:
            if port == 465:
                with smtplib.SMTP_SSL(smtp_host, port, timeout=20) as smtp:
                    smtp.login(smtp_user, smtp_pass)
                    smtp.send_message(message)
            else:
                with smtplib.SMTP(smtp_host, port, timeout=20) as smtp:
                    smtp.starttls()
                    smtp.login(smtp_user, smtp_pass)
                    smtp.send_message(message)
            return "SENT", "smtp"
        except Exception as exc:
            app_log("SMTP send failed", attempt=attempt+1, error=str(exc))
            if attempt == 1:
                return "FAILED", "smtp"
            time.sleep(2)
    return "FAILED", "smtp"

def send_whatsapp_provider(to_phone, content):
    cleaned = sanitize_phone(to_phone)
    if not valid_phone(cleaned):
        return "FAILED", "validation"

    twilio_sid = os.environ.get("TWILIO_ACCOUNT_SID")
    twilio_token = os.environ.get("TWILIO_AUTH_TOKEN")
    twilio_from = os.environ.get("TWILIO_WHATSAPP_FROM")
    if twilio_sid and twilio_token and twilio_from:
        endpoint = f"https://api.twilio.com/2010-04-01/Accounts/{twilio_sid}/Messages.json"
        payload = urllib.parse.urlencode(
            {
                "From": f"whatsapp:{twilio_from}",
                "To": f"whatsapp:{cleaned}",
                "Body": content[:1500],
            }
        ).encode("utf-8")
        auth_token = base64.b64encode(f"{twilio_sid}:{twilio_token}".encode("utf-8")).decode("utf-8")
        request_obj = urllib.request.Request(
            endpoint,
            data=payload,
            headers={"Authorization": f"Basic {auth_token}", "Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        twilio_context = None
        if str(os.environ.get("TWILIO_INSECURE_TLS", "false")).strip().lower() in ("1", "true", "yes", "on"):
            twilio_context = ssl._create_unverified_context()
        elif certifi:
            twilio_context = ssl.create_default_context(cafile=certifi.where())
        for attempt in range(2):
            try:
                with urllib.request.urlopen(request_obj, timeout=25, context=twilio_context):
                    return "SENT", "twilio"
            except Exception as exc:
                app_log("Twilio WhatsApp send failed", attempt=attempt + 1, error=str(exc))
                if attempt == 0:
                    time.sleep(1)
        return "FAILED", "twilio"

    token = os.environ.get("META_WHATSAPP_TOKEN")
    phone_number_id = os.environ.get("META_PHONE_NUMBER_ID")
    if not token or not phone_number_id:
        return "DELIVERED", "simulated"

    payload = json.dumps(
        {
            "messaging_product": "whatsapp",
            "to": cleaned.replace("+", ""),
            "type": "text",
            "text": {"preview_url": False, "body": content},
        }
    ).encode("utf-8")
    request_obj = urllib.request.Request(
        f"https://graph.facebook.com/v19.0/{phone_number_id}/messages",
        data=payload,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request_obj, timeout=25):
                return "SENT", "meta"
        except Exception as exc:
            app_log("WhatsApp send failed", attempt=attempt+1, error=str(exc))
            if attempt == 1:
                return "FAILED", "meta"
            time.sleep(2)
    return "FAILED", "meta"

def add_email_to_state(state, to_email, subject, content, linked="", status="SENT", provider="simulated"):
    state_lists(state)
    email = {
        "id": next_id("e"),
        "from": os.environ.get("SMTP_FROM", "sales@jkfluidcontrols.com"),
        "to": to_email,
        "subject": subject,
        "body": content,
        "status": status,
        "provider": provider,
        "linkedTo": linked,
        "createdAt": now(),
    }
    state["emails"].append(email)
    return email

def add_whatsapp_to_state(state, contact_id, to_phone, content, direction="OUT", bot=False, status="SENT", provider="simulated"):
    state_lists(state)
    msg = {
        "id": next_id("m"),
        "contactId": contact_id,
        "to": to_phone,
        "body": content,
        "direction": direction,
        "bot": bool(bot),
        "status": status,
        "provider": provider,
        "createdAt": now(),
    }
    state["messages"].append(msg)
    return msg

def state_lists(state):
    for key in ("emails", "messages", "activities", "audit", "automationLog"):
        if not isinstance(state.get(key), list):
            state[key] = []
    if not isinstance(state.get("automations"), list):
        state["automations"] = []

def default_state_payload():
    return json_clone(load_state("default") or {})

def extract_openai_text(payload):
    choices = payload.get("choices") or []
    if choices:
        return choices[0].get("message", {}).get("content", "").strip()
    return ""

def canonical_record_timestamp(record):
    for key in ("updatedAt", "updated_at", "createdAt", "created_at", "at", "time"):
        parsed = parse_datetime(record.get(key) if isinstance(record, dict) else None)
        if parsed:
            return parsed
    return datetime.min

def record_sort_key(record):
    timestamp = canonical_record_timestamp(record)
    identifier = text_value((record or {}).get("id"), max_len=180)
    return (timestamp, identifier)

def sort_collection_items(items):
    return sorted(items or [], key=record_sort_key, reverse=True)

def collections_with_versions():
    return (
        "companies",
        "contacts",
        "inquiries",
        "pipeline",
        "quotations",
        "orders",
        "activities",
        "messages",
        "emails",
        "automations",
        "automationLog",
        "audit",
    )

def rate_limit_allowed(identity, bucket, limit, window_seconds):
    now_ts = time.time()
    key = f"{bucket}:{identity}"
    with REQUEST_RATE_LOCK:
        history = [ts for ts in REQUEST_RATE_LIMIT.get(key, []) if now_ts - ts < window_seconds]
        if len(history) >= limit:
            REQUEST_RATE_LIMIT[key] = history
            return False
        history.append(now_ts)
        REQUEST_RATE_LIMIT[key] = history
    return True

def record_without_mutation_fields(record):
    if not isinstance(record, dict):
        return {}
    ignored = {"updatedAt", "updated_at", "createdAt", "created_at", "version"}
    return {key: value for key, value in record.items() if key not in ignored}

def detect_locked_inquiry_changes(current, incoming):
    current_inquiries = {
        text_value(item.get("id"), max_len=120): item
        for item in (current.get("inquiries") if isinstance(current.get("inquiries"), list) else [])
        if isinstance(item, dict)
    }
    for item in incoming.get("inquiries") if isinstance(incoming.get("inquiries"), list) else []:
        if not isinstance(item, dict):
            continue
        inquiry_id = text_value(item.get("id"), max_len=120)
        current_item = current_inquiries.get(inquiry_id)
        if not current_item or not boolean_value(current_item.get("isLocked")):
            continue
        if record_without_mutation_fields(item) != record_without_mutation_fields(current_item):
            raise ConflictError(f"Inquiry {current_item.get('no') or inquiry_id} is locked after quotation conversion.")

def enforce_idempotent_relationships(current, merged):
    current_quotes = {
        text_value(item.get("inquiryId"), max_len=120): item
        for item in (current.get("quotations") if isinstance(current.get("quotations"), list) else [])
        if isinstance(item, dict) and text_value(item.get("inquiryId"), max_len=120)
    }
    current_orders = {
        text_value(item.get("quotationId"), max_len=120): item
        for item in (current.get("orders") if isinstance(current.get("orders"), list) else [])
        if isinstance(item, dict) and text_value(item.get("quotationId"), max_len=120)
    }

    merged_quotes = []
    seen_inquiry_ids = set()
    for item in merged.get("quotations") if isinstance(merged.get("quotations"), list) else []:
        if not isinstance(item, dict):
            continue
        inquiry_id = text_value(item.get("inquiryId"), max_len=120)
        if inquiry_id and inquiry_id in current_quotes and text_value(item.get("id"), max_len=120) != text_value(current_quotes[inquiry_id].get("id"), max_len=120):
            if inquiry_id not in seen_inquiry_ids:
                merged_quotes.append(json_clone(current_quotes[inquiry_id]))
                seen_inquiry_ids.add(inquiry_id)
            continue
        if inquiry_id:
            if inquiry_id in seen_inquiry_ids:
                continue
            seen_inquiry_ids.add(inquiry_id)
        merged_quotes.append(item)
    for inquiry_id, item in current_quotes.items():
        if inquiry_id and inquiry_id not in seen_inquiry_ids:
            merged_quotes.append(json_clone(item))
    merged["quotations"] = merged_quotes

    merged_orders = []
    seen_quotation_ids = set()
    for item in merged.get("orders") if isinstance(merged.get("orders"), list) else []:
        if not isinstance(item, dict):
            continue
        quotation_id = text_value(item.get("quotationId"), max_len=120)
        if quotation_id and quotation_id in current_orders and text_value(item.get("id"), max_len=120) != text_value(current_orders[quotation_id].get("id"), max_len=120):
            if quotation_id not in seen_quotation_ids:
                merged_orders.append(json_clone(current_orders[quotation_id]))
                seen_quotation_ids.add(quotation_id)
            continue
        if quotation_id:
            if quotation_id in seen_quotation_ids:
                continue
            seen_quotation_ids.add(quotation_id)
        merged_orders.append(item)
    for quotation_id, item in current_orders.items():
        if quotation_id and quotation_id not in seen_quotation_ids:
            merged_orders.append(json_clone(item))
    merged["orders"] = merged_orders
    return merged

def apply_versions(current, sanitized):
    current = current if isinstance(current, dict) else {}
    for collection in collections_with_versions():
        previous = {
            text_value(item.get("id"), max_len=120): item
            for item in (current.get(collection) if isinstance(current.get(collection), list) else [])
            if isinstance(item, dict)
        }
        updated = []
        for item in sanitized.get(collection) if isinstance(sanitized.get(collection), list) else []:
            if not isinstance(item, dict):
                continue
            record_id = text_value(item.get("id"), max_len=120)
            existing = previous.get(record_id)
            base = dict(item)
            if existing:
                if record_without_mutation_fields(base) == record_without_mutation_fields(existing):
                    base["version"] = integer_value(existing.get("version"), 1)
                    base["createdAt"] = text_value(existing.get("createdAt"), text_value(base.get("createdAt"), now(), 40), 40)
                    base["updatedAt"] = text_value(existing.get("updatedAt"), text_value(base.get("updatedAt"), now(), 40), 40)
                else:
                    base["version"] = integer_value(existing.get("version"), 1) + 1
                    base["createdAt"] = text_value(existing.get("createdAt"), text_value(base.get("createdAt"), now(), 40), 40)
                    base["updatedAt"] = iso_now()
            else:
                base["version"] = max(1, integer_value(base.get("version"), 1))
                base["createdAt"] = text_value(base.get("createdAt"), iso_now(), 40)
                base["updatedAt"] = text_value(base.get("updatedAt"), base["createdAt"], 40)
            updated.append(base)
        sanitized[collection] = updated
    return sanitized

def audit_state_changes(user, current, updated):
    user_id = text_value(user.get("sub") or user.get("email"), "anonymous", 180)
    action_map = {
        "companies": "company",
        "contacts": "contact",
        "inquiries": "inquiry",
        "quotations": "quotation",
        "orders": "order",
    }
    for collection, entity_type in action_map.items():
        previous = {
            text_value(item.get("id"), max_len=120): item
            for item in (current.get(collection) if isinstance(current.get(collection), list) else [])
            if isinstance(item, dict)
        }
        latest = {
            text_value(item.get("id"), max_len=120): item
            for item in (updated.get(collection) if isinstance(updated.get(collection), list) else [])
            if isinstance(item, dict)
        }
        for entity_id, record in latest.items():
            before = previous.get(entity_id)
            if not before:
                action = "create"
                if collection == "quotations" and text_value(record.get("inquiryId"), max_len=120):
                    action = "convert"
                if collection == "orders":
                    action = "order_create"
                log_activity_event(user_id, action, entity_type, entity_id, {"number": record.get("no")})
                continue
            if record_without_mutation_fields(before) != record_without_mutation_fields(record):
                log_activity_event(user_id, "update", entity_type, entity_id, {"number": record.get("no")})
        for entity_id, record in previous.items():
            if entity_id not in latest:
                log_activity_event(user_id, "delete", entity_type, entity_id, {"number": record.get("no")})

def sanitize_crm_state(payload, user=None):
    state = payload if isinstance(payload, dict) else {}
    sanitized = {}
    default_loaded = {key: False for key in STATE_COLLECTION_KEYS}
    if isinstance(state.get("loadedCollections"), dict):
        default_loaded.update({key: boolean_value(value) for key, value in state.get("loadedCollections", {}).items()})
    else:
        default_loaded.update({key: True for key in STATE_COLLECTION_KEYS if key in state})
    sanitized["loadedCollections"] = default_loaded
    sanitized["theme"] = "dark" if text_value(state.get("theme"), "light", 10) == "dark" else "light"
    sanitized["selectedContactId"] = text_value(state.get("selectedContactId"), max_len=120)
    sanitized["summary"] = state.get("summary") if isinstance(state.get("summary"), dict) else {}
    sanitized["pagination"] = state.get("pagination") if isinstance(state.get("pagination"), dict) else {}

    # 1. Companies
    companies = []
    for item in state.get("companies") if isinstance(state.get("companies"), list) else []:
        if not isinstance(item, dict):
            continue
        c_id = text_value(item.get("id"), max_len=120)
        if not c_id:
            continue
        companies.append(
            {
                "id": c_id,
                "name": text_value(item.get("name"), "Unnamed Company", 180),
                "industry": text_value(item.get("industry"), "Industrial Valve", 120),
                "size": text_value(item.get("size"), "Medium", 60),
                "website": text_value(item.get("website"), "", 200),
                "location": text_value(item.get("location"), "", 200),
                "status": sanitize_status(item.get("status"), {"LEAD", "CUSTOMER", "INACTIVE"}, "LEAD"),
                "city": text_value(item.get("city"), "", 120),
                "state": text_value(item.get("state"), "", 120),
                "country": text_value(item.get("country"), "India", 120),
                "phone": text_value(item.get("phone"), "", 60),
                "email": text_value(item.get("email"), "", 180).lower(),
                "gst": text_value(item.get("gst"), "", 60),
                "assignedTo": text_value(item.get("assignedTo"), "", 180),
                "tags": [text_value(t, max_len=60) for t in item.get("tags") if t] if isinstance(item.get("tags"), list) else [],
                "version": integer_value(item.get("version"), 1),
                "createdAt": text_value(item.get("createdAt"), now(), 40),
                "updatedAt": text_value(item.get("updatedAt"), now(), 40),
            }
        )
    sanitized["companies"] = companies

    # 2. Contacts
    contacts = []
    company_ids = {c["id"] for c in companies}
    for item in state.get("contacts") if isinstance(state.get("contacts"), list) else []:
        if not isinstance(item, dict):
            continue
        co_id = text_value(item.get("id"), max_len=120)
        c_id = text_value(item.get("companyId"), max_len=120)
        if not co_id or not c_id or c_id not in company_ids:
            continue
        first = text_value(item.get("first"), max_len=120)
        last = text_value(item.get("last"), max_len=120)
        contacts.append(
            {
                "id": co_id,
                "companyId": c_id,
                "first": first,
                "last": last,
                "name": text_value(item.get("name"), f"{first} {last}".strip() or "Staff Member", 200),
                "designation": text_value(item.get("designation"), "Representative", 120),
                "email": text_value(item.get("email"), "", 180).lower(),
                "phone": text_value(item.get("phone"), "", 60),
                "whatsapp": text_value(item.get("whatsapp"), "", 60),
                "primary": boolean_value(item.get("primary")),
                "waOptIn": boolean_value(item.get("waOptIn", True)),
                "version": integer_value(item.get("version"), 1),
                "createdAt": text_value(item.get("createdAt"), now(), 40),
                "updatedAt": text_value(item.get("updatedAt"), now(), 40),
            }
        )
    sanitized["contacts"] = contacts

    # 3. Stages
    stages = []
    for item in state.get("stages") if isinstance(state.get("stages"), list) else []:
        if not isinstance(item, dict):
            continue
        stages.append(
            {
                "id": text_value(item.get("id"), max_len=80),
                "name": text_value(item.get("name"), "Stage", 120),
                "color": text_value(item.get("color"), "#cbd5e1", 30),
                "order": integer_value(item.get("order"), 0),
            }
        )
    if not stages:
        stages = [
            {"id": "new", "name": "New Inquiry", "color": "#3b82f6", "order": 1},
            {"id": "quote_draft", "name": "Quote Draft", "color": "#eab308", "order": 2},
            {"id": "quote_sent", "name": "Quote Sent", "color": "#06b6d4", "order": 3},
            {"id": "negotiation", "name": "Negotiation", "color": "#f97316", "order": 4},
            {"id": "won", "name": "Order Won", "color": "#22c55e", "order": 5},
            {"id": "lost", "name": "Closed Lost", "color": "#ef4444", "order": 6},
        ]
    sanitized["stages"] = sorted(stages, key=lambda s: s["order"])
    stage_ids = {s["id"] for s in sanitized["stages"]}

    # 4. Inquiries / Leads
    inquiries = []
    for item in state.get("inquiries") if isinstance(state.get("inquiries"), list) else []:
        if not isinstance(item, dict):
            continue
        inq_id = text_value(item.get("id"), max_len=120)
        c_id = text_value(item.get("companyId"), max_len=120)
        if not inq_id or not c_id or c_id not in company_ids:
            continue
        no = text_value(item.get("no"), max_len=80)
        if not no:
            no = next_inquiry_no({"inquiries": inquiries})
        inquiries.append(
            {
                "id": inq_id,
                "no": no,
                "companyId": c_id,
                "contactId": text_value(item.get("contactId"), max_len=120),
                "assignedTo": text_value(item.get("assignedTo"), "", 180),
                "status": sanitize_status(item.get("status"), {"NEW", "CONTACTED", "QUALIFIED", "UNQUALIFIED", "WON", "LOST"}, "NEW"),
                "priority": sanitize_status(item.get("priority"), {"LOW", "MEDIUM", "HIGH", "CRITICAL"}, "MEDIUM"),
                "source": text_value(item.get("source"), "Direct", 80),
                "projectType": text_value(item.get("projectType"), "", 120),
                "budgetMin": numeric_value(item.get("budgetMin"), 0.0),
                "budgetMax": numeric_value(item.get("budgetMax"), 0.0),
                "requiredDate": text_value(item.get("requiredDate"), "", 40),
                "requirements": text_value(item.get("requirements"), max_len=2000),
                "notes": text_value(item.get("notes"), max_len=2000),
                "isLocked": boolean_value(item.get("isLocked")),
                "products": sanitize_products(item.get("products"), inq_id),
                "version": integer_value(item.get("version"), 1),
                "createdAt": text_value(item.get("createdAt"), now(), 40),
                "updatedAt": text_value(item.get("updatedAt"), now(), 40),
            }
        )
    sanitized["inquiries"] = inquiries
    inq_map = {item["id"]: item for item in inquiries}

    # 5. Products list (derived)
    products = []
    for item in inquiries:
        for p in item.get("products") or []:
            products.append({**p, "inquiryId": item["id"], "inquiryNo": item["no"]})
    sanitized["products"] = products

    # 6. Quotations
    quotations = []
    for item in state.get("quotations") if isinstance(state.get("quotations"), list) else []:
        if not isinstance(item, dict):
            continue
        q_id = text_value(item.get("id"), max_len=120)
        c_id = text_value(item.get("companyId"), max_len=120)
        if not q_id or not c_id or c_id not in company_ids:
            continue
        no = text_value(item.get("no"), max_len=80)
        if not no:
            no = next_quotation_no({"quotations": quotations})
        quotations.append(
            {
                "id": q_id,
                "no": no,
                "inquiryId": text_value(item.get("inquiryId"), max_len=120),
                "companyId": c_id,
                "status": sanitize_status(item.get("status"), {"DRAFT", "SENT", "ACCEPTED", "DECLINED", "EXPIRED"}, "DRAFT"),
                "validUntil": text_value(item.get("validUntil"), "", 40),
                "discount": numeric_value(item.get("discount"), 0.0),
                "paymentTerms": text_value(item.get("paymentTerms"), "Net 30", 180),
                "sentAt": text_value(item.get("sentAt"), "", 40),
                "products": sanitize_products(item.get("products"), q_id),
                "totalAmount": numeric_value(item.get("totalAmount"), 0.0),
                "version": integer_value(item.get("version"), 1),
                "createdAt": text_value(item.get("createdAt"), now(), 40),
                "updatedAt": text_value(item.get("updatedAt"), now(), 40),
            }
        )
    sanitized["quotations"] = quotations
    quote_map = {item["id"]: item for item in quotations}

    # 7. Quote Items list (derived)
    quote_items = []
    for item in quotations:
        for p in item.get("products") or []:
            quote_items.append({**p, "quotationId": item["id"], "quotationNo": item["no"]})
    sanitized["quoteItems"] = quote_items

    # 8. Orders
    orders = []
    for item in state.get("orders") if isinstance(state.get("orders"), list) else []:
        if not isinstance(item, dict):
            continue
        o_id = text_value(item.get("id"), max_len=120)
        c_id = text_value(item.get("companyId"), max_len=120)
        q_id = text_value(item.get("quotationId"), max_len=120)
        if not o_id or not c_id or c_id not in company_ids or not q_id or q_id not in quote_map:
            continue
        no = text_value(item.get("no"), max_len=80)
        if not no:
            no = next_order_no({"orders": orders})
        orders.append(
            {
                "id": o_id,
                "no": no,
                "quotationId": q_id,
                "companyId": c_id,
                "po": text_value(item.get("po"), max_len=120),
                "status": sanitize_status(item.get("status"), {"CONFIRMED", "DISPATCHED", "DELIVERED", "CANCELLED"}, "CONFIRMED"),
                "payment": sanitize_status(item.get("payment"), {"PENDING", "PARTIAL", "PAID", "REFUNDED"}, "PENDING"),
                "courier": text_value(item.get("courier"), "", 120),
                "tracking": text_value(item.get("tracking"), "", 120),
                "dispatchDate": text_value(item.get("dispatchDate"), "", 40),
                "expectedDelivery": text_value(item.get("expectedDelivery"), "", 40),
                "products": sanitize_products(item.get("products"), o_id),
                "value": numeric_value(item.get("value"), 0.0),
                "amount": numeric_value(item.get("amount"), 0.0),
                "version": integer_value(item.get("version"), 1),
                "createdAt": text_value(item.get("createdAt"), now(), 40),
                "updatedAt": text_value(item.get("updatedAt"), now(), 40),
            }
        )
    sanitized["orders"] = orders

    # 9. Pipeline Deals (derived dynamically)
    pipeline = []
    for item in inquiries:
        stage_id = "new"
        if item["status"] == "WON":
            stage_id = "won"
        elif item["status"] == "LOST":
            stage_id = "lost"
        elif item["status"] == "CONTACTED":
            stage_id = "quote_draft"
        elif item["status"] == "QUALIFIED":
            stage_id = "quote_sent"
        
        # Override based on quotes or orders
        has_sent_quote = any(q["inquiryId"] == item["id"] and q["status"] == "SENT" for q in quotations)
        has_won_quote = any(q["inquiryId"] == item["id"] and q["status"] == "ACCEPTED" for q in quotations)
        if has_won_quote:
            stage_id = "won"
        elif has_sent_quote:
            stage_id = "quote_sent"
            
        co = find_company(sanitized, item["companyId"])
        val = sum(p.get("price", 0.0) * p.get("quantity", 1) for p in item.get("products") or [])
        pipeline.append(
            {
                "id": f"deal-{item['id']}",
                "title": f"{co.get('name', 'Client')} - {item['no']}",
                "value": round(val, 2),
                "stageId": stage_id,
                "companyId": item["companyId"],
                "inquiryId": item["id"],
                "assignedTo": item["assignedTo"],
                "updatedAt": item["updatedAt"],
            }
        )
    sanitized["pipeline"] = pipeline

    # 10. Activities
    activities = []
    for item in state.get("activities") if isinstance(state.get("activities"), list) else []:
        if not isinstance(item, dict):
            continue
        act_id = text_value(item.get("id"), max_len=120)
        if not act_id:
            continue
        activities.append(
            {
                "id": act_id,
                "type": text_value(item.get("type"), "task", 60),
                "title": text_value(item.get("title"), "Follow Up Activity", 200),
                "companyId": text_value(item.get("companyId"), max_len=120),
                "contactId": text_value(item.get("contactId"), max_len=120),
                "inquiryId": text_value(item.get("inquiryId"), max_len=120),
                "owner": text_value(item.get("owner"), "", 180),
                "due": text_value(item.get("due"), today_iso(), 40),
                "outcome": text_value(item.get("outcome"), max_len=1000),
                "done": boolean_value(item.get("done")),
                "version": integer_value(item.get("version"), 1),
                "createdAt": text_value(item.get("createdAt"), now(), 40),
                "updatedAt": text_value(item.get("updatedAt"), now(), 40),
            }
        )
    sanitized["activities"] = activities

    # 11. Messages
    messages = []
    for item in state.get("messages") if isinstance(state.get("messages"), list) else []:
        if not isinstance(item, dict):
            continue
        m_id = text_value(item.get("id"), max_len=120)
        if not m_id:
            continue
        messages.append(
            {
                "id": m_id,
                "contactId": text_value(item.get("contactId"), max_len=120),
                "to": text_value(item.get("to"), max_len=60),
                "body": text_value(item.get("body"), max_len=2000),
                "direction": sanitize_status(item.get("direction"), {"IN", "OUT"}, "OUT"),
                "bot": boolean_value(item.get("bot")),
                "status": text_value(item.get("status"), "SENT", 40),
                "provider": text_value(item.get("provider"), "simulated", 60),
                "createdAt": text_value(item.get("createdAt"), now(), 40),
            }
        )
    sanitized["messages"] = messages

    # 12. Emails
    emails = []
    for item in state.get("emails") if isinstance(state.get("emails"), list) else []:
        if not isinstance(item, dict):
            continue
        e_id = text_value(item.get("id"), max_len=120)
        if not e_id:
            continue
        emails.append(
            {
                "id": e_id,
                "from": text_value(item.get("from"), "sales@jkfluidcontrols.com", 180),
                "to": text_value(item.get("to"), "", 180),
                "subject": text_value(item.get("subject"), "CRM Message", 240),
                "body": text_value(item.get("body"), max_len=10000),
                "status": text_value(item.get("status"), "SENT", 40),
                "provider": text_value(item.get("provider"), "simulated", 60),
                "linkedTo": text_value(item.get("linkedTo"), "", 120),
                "createdAt": text_value(item.get("createdAt"), now(), 40),
            }
        )
    sanitized["emails"] = emails

    # 13. Automations
    automations = []
    for item in state.get("automations") if isinstance(state.get("automations"), list) else []:
        if not isinstance(item, dict):
            continue
        automations.append(
            {
                "id": text_value(item.get("id"), max_len=80),
                "name": text_value(item.get("name"), "Automation Rule", 120),
                "trigger": sanitize_status(item.get("trigger"), {"INQUIRY_CREATED", "QUOTE_SENT", "ORDER_DELIVERED"}, "QUOTE_SENT"),
                "active": boolean_value(item.get("active")),
                "delayHours": integer_value(item.get("delayHours"), 24),
                "condition": sanitize_status(item.get("condition"), {"ALWAYS", "NO_REPLY"}, "ALWAYS"),
                "steps": text_value(item.get("steps"), max_len=600),
            }
        )
    if not automations:
        state_lists(sanitized)
        automations = sanitized["automations"]
    sanitized["automations"] = automations

    # 14. Automation Log
    log_arr = []
    for item in state.get("automationLog") if isinstance(state.get("automationLog"), list) else []:
        if not isinstance(item, dict):
            continue
        log_arr.append(
            {
                "id": text_value(item.get("id"), max_len=120),
                "ruleId": text_value(item.get("ruleId"), max_len=80),
                "ruleName": text_value(item.get("ruleName"), max_len=120),
                "entityId": text_value(item.get("entityId"), max_len=120),
                "action": text_value(item.get("action"), max_len=200),
                "status": text_value(item.get("status"), max_len=60),
                "detail": text_value(item.get("detail"), max_len=1000),
                "at": text_value(item.get("at"), now(), 40),
            }
        )
    sanitized["automationLog"] = log_arr

    # 15. Audit log
    audit_arr = []
    for item in state.get("audit") if isinstance(state.get("audit"), list) else []:
        if not isinstance(item, dict):
            continue
        audit_arr.append(
            {
                "id": text_value(item.get("id"), max_len=120),
                "user": text_value(item.get("user"), max_len=180),
                "action": text_value(item.get("action"), max_len=200),
                "entity": text_value(item.get("entity"), max_len=120),
                "at": text_value(item.get("at"), now(), 40),
            }
        )
    sanitized["audit"] = audit_arr

    return sanitized

def sanitize_status(value, allowed_set, default):
    text = str(value or "").strip().upper()
    return text if text in allowed_set else default

def run_automation(state, state_id):
    automations = state.get("automations", [])
    inquiries = state.get("inquiries", [])
    quotations = state.get("quotations", [])
    orders = state.get("orders", [])
    emails = state.get("emails", [])
    messages = state.get("messages", [])
    logs = state.get("automationLog", [])
    if not isinstance(logs, list):
        logs = []
    
    results = []
    
    for rule in automations:
        if not boolean_value(rule.get("active")):
            continue
        trigger = rule.get("trigger")
        delay = float(rule.get("delayHours") or 0)
        condition = rule.get("condition", "ALWAYS")
        steps = str(rule.get("steps") or "")
        
        if trigger == "QUOTE_SENT":
            for quote in quotations:
                if quote.get("status") != "SENT":
                    continue
                # check delay hours elapsed
                hours = elapsed_hours_since(quote.get("sentAt") or quote.get("updatedAt"))
                if hours < delay:
                    continue
                    
                # check condition
                if condition == "NO_REPLY":
                    # Check if any outbound email/whatsapp sent recently or lead updated
                    has_reply = False
                    for email in emails:
                        if email.get("linkedTo") == quote.get("id") and email.get("direction", "OUT") == "IN":
                            has_reply = True
                    if has_reply:
                        continue
                        
                # run step
                log_id = next_id("alog")
                logs.append({
                    "id": log_id,
                    "ruleId": rule.get("id"),
                    "ruleName": rule.get("name"),
                    "entityId": quote.get("id"),
                    "action": "Triggered followup steps",
                    "status": "COMPLETED",
                    "detail": f"Completed steps: {steps}",
                    "at": now()
                })
                results.append(f"Quotation {quote.get('no')} follow-up triggered.")
                
    state["automationLog"] = logs
    return state, results

# Scheduler Loop
def run_due_followups():
    state = load_state() or {}
    with db() as connection:
        if db_engine() == "postgres":
            rows = connection.execute(
                """
                SELECT lead_id, last_contacted, follow_up_due, follow_up_sent
                FROM lead_followups
                WHERE follow_up_sent = 0 AND follow_up_due <= %s
                ORDER BY follow_up_due ASC
                FOR UPDATE SKIP LOCKED
                """,
                (now(),),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT lead_id, last_contacted, follow_up_due, follow_up_sent
                FROM lead_followups
                WHERE follow_up_sent = 0 AND follow_up_due <= ?
                ORDER BY follow_up_due ASC
                """,
                (now(),),
            ).fetchall()
            
        due = [dict(row) for row in rows]
        for item in due:
            lead_id = str(item.get("lead_id") or "")
            if not lead_id:
                continue
            
            # Immediately update status to 1 to lock other processes/workers from picking it up
            connection.execute(
                q("UPDATE lead_followups SET follow_up_sent = 1, updated_at = ? WHERE lead_id = ?"),
                (now(), lead_id),
            )
            connection.commit()
            
            target = resolve_lead_targets(state, lead_id)
            prompt = f"Draft a concise follow-up message for lead {lead_id}."
            message, provider, _, reason = generate_message_safe(lead_id, prompt, state, "scheduler", "assistant")
            sent = False
            channel = "NONE"
            status = "SKIPPED"
            if target.get("email"):
                email_status, email_provider = send_email_provider(target["email"], f"Follow-up for {lead_id}", message)
                channel = "EMAIL"
                sent = email_status in ("SENT", "SIMULATED")
                status = email_status
                create_activity(lead_id, "FOLLOW_UP_TRIGGERED", status, f"email={target['email']}", {"provider": email_provider, "ai_provider": provider, "fallback_reason": reason})
            elif valid_phone(target.get("phone")):
                wa_status, wa_provider = send_whatsapp_provider(target["phone"], message)
                channel = "WHATSAPP"
                sent = wa_status in ("SENT", "DELIVERED")
                status = wa_status
                create_activity(lead_id, "FOLLOW_UP_TRIGGERED", status, f"phone={target['phone']}", {"provider": wa_provider, "ai_provider": provider, "fallback_reason": reason})
            else:
                create_activity(lead_id, "FOLLOW_UP_TRIGGERED", "FAILED", "No email/phone target found", {"ai_provider": provider})
                
            if sent:
                app_log("Follow-up sent", lead_id=lead_id, channel=channel, status=status)
            else:
                # Revert update if failed to send
                with db() as conn2:
                    conn2.execute(
                        q("UPDATE lead_followups SET follow_up_sent = 0, updated_at = ? WHERE lead_id = ?"),
                        (now(), lead_id),
                    )
                    conn2.commit()

def resolve_lead_targets(state, lead_id):
    inquiries = state.get("inquiries", []) if state else []
    inquiry = next((item for item in inquiries if item.get("id") == lead_id or item.get("no") == lead_id), None)
    if not inquiry:
        return {"email": "", "phone": "", "name": "Client"}
    company = find_company(state, inquiry.get("companyId"))
    contact = find_contact(state, inquiry.get("contactId")) or primary_contact_for_company(state, inquiry.get("companyId"))
    return {
        "email": company.get("email", ""),
        "phone": contact.get("whatsapp") or contact.get("phone", ""),
        "name": contact.get("first") or company.get("name") or "Client",
    }

def followup_scheduler_loop():
    interval_seconds = int(os.environ.get("FOLLOWUP_POLL_SECONDS", "3600"))
    app_log("Follow-up scheduler started", interval_seconds=interval_seconds)
    while True:
        try:
            run_due_followups()
        except Exception as exc:
            app_log("Follow-up scheduler error", error=str(exc), level=logging.ERROR)
        time.sleep(max(60, interval_seconds))

# Flask Setup
app = Flask(__name__, static_folder=None)
CORS(
    app,
    resources={r"/api/*": {"origins": [
        "https://jk-crm.vercel.app",
        "https://jk-fluid-control.vercel.app",
        "http://localhost:5173",
        "http://localhost:3000"
    ]}},
    supports_credentials=True
)

# Request filters & Rate limit checks
@app.before_request
def handle_before_request():
    request.start_time = time.time()
    
    # Rate Limits
    if request.path == "/api/auth/login":
        ip = request.remote_addr
        if not check_rate_limit(ip, LOGIN_LIMITS, max_requests=5, window_seconds=60):
            app_log("Rate limit exceeded for login", ip=ip, level=logging.WARNING)
            return jsonify({"error": "Too many failed login attempts. Please try again later."}), 429
            
    elif request.path == "/api/generate-message":
        ip = request.remote_addr
        if not check_rate_limit(ip, GENERATE_LIMITS, max_requests=10, window_seconds=60):
            app_log("Rate limit exceeded for generate-message", ip=ip, level=logging.WARNING)
            return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429

    # Idempotency Cache
    idem_key = request.headers.get("Idempotency-Key")
    if idem_key and idem_key in _idempotency_cache:
        cached = _idempotency_cache[idem_key]
        response = jsonify(cached["body"])
        response.status_code = 200
        for k, v in cached["headers"].items():
            response.headers[k] = v
        response.headers["X-Cache-Lookup"] = "HIT"
        return response

_idempotency_cache = {}

@app.after_request
def handle_after_request(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # Clean up duplicate CORS Access-Control-Allow-Origin headers
    origins = response.headers.getlist("Access-Control-Allow-Origin")
    if len(origins) > 1 or (origins and "*" in origins):
        response.headers.pop("Access-Control-Allow-Origin", None)
        origin = request.headers.get("Origin")
        allowed_origins = [
            "https://jk-crm.vercel.app",
            "https://jk-fluid-control.vercel.app",
            "http://localhost:5173",
            "http://localhost:3000"
        ]
        if origin in allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
    
    idem_key = request.headers.get("Idempotency-Key")
    if idem_key and idem_key not in _idempotency_cache:
        try:
            body = json.loads(response.get_data(as_text=True))
        except Exception:
            body = response.get_data(as_text=True)
        _idempotency_cache[idem_key] = {
            "body": body,
            "status": response.status_code,
            "headers": dict(response.headers)
        }
        
    duration = int((time.time() - getattr(request, "start_time", time.time())) * 1000)
    user_id = "anonymous"
    if hasattr(g, "user") and g.user:
        user_id = g.user.get("sub") or "anonymous"
    
    if request.path.startswith("/api/"):
        log_structured(
            action=f"request_{request.method}_{request.path}",
            user_id=user_id,
            duration_ms=duration,
            status_code=response.status_code,
            extra={"ip": request.remote_addr}
        )
        log_api(request.method, request.path, response.status_code)
        
    return response

# Auth Decorator
def require_auth_decorator(allowed_roles=None):
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated(*args, **kwargs):
            user = None
            auth_header = request.headers.get("Authorization", "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()
                payload = verify_token(token, auth_secret())
                if payload:
                    user = {
                        "sub": payload.get("sub"),
                        "email": payload.get("email"),
                        "role": payload.get("role"),
                        "name": payload.get("name"),
                        "workspace_id": request.headers.get("X-Workspace-Id") or None
                    }
            if not user:
                return jsonify({"error": "Unauthorized"}), 401
                
            if allowed_roles and user["role"] not in allowed_roles:
                return jsonify({"error": f"Forbidden: role '{user['role']}' does not have access"}), 403
                
            if request.method in ("POST", "PUT", "PATCH", "DELETE") and user["role"] == "VIEWER":
                return jsonify({"error": "Forbidden: VIEWER role cannot modify data"}), 403
                
            g.user = user
            return f(*args, **kwargs)
        return decorated
    return decorator

# API Routes
@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "ok": True,
        "database": database_label(),
        "database_engine": db_engine(),
        "database_driver": "psycopg" if db_engine() == "postgres" else "sqlite3",
        "database_ready": db_available(),
        "supabase_validated": validate_supabase_url(),
        "ai": "openai" if os.environ.get("OPENAI_API_KEY") else "fallback",
        "email": "smtp" if os.environ.get("SMTP_HOST") else "simulated",
        "whatsapp": "meta" if os.environ.get("META_WHATSAPP_TOKEN") and os.environ.get("META_PHONE_NUMBER_ID") else "simulated",
    })

@app.route("/api/db/health", methods=["GET"])
def api_db_health():
    status = "healthy"
    error = None
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
    except Exception as e:
        status = "unhealthy"
        error = str(e)
    return jsonify({"status": status, "engine": db_engine(), "error": error}), 200 if status == "healthy" else 503

@app.route("/api/summary", methods=["GET"])
@require_auth_decorator()
def api_summary():
    return jsonify({"summary": crm_summary(resolve_request_state(g.user))})

@app.route("/api/state", methods=["GET", "PUT"])
@require_auth_decorator()
def api_state():
    user = g.user
    if request.method == "GET":
        return jsonify({"state": resolve_request_state(user)})
    elif request.method == "PUT":
        body = request.get_json() or {}
        payload = body.get("state", body)
        if not isinstance(payload, dict):
            return jsonify({"error": "State payload must be an object"}), 400
        try:
            state = resolve_request_state(user, payload, persist=True)
            return jsonify({"ok": True, "updatedAt": now(), "state": state})
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        except ConflictError as exc:
            return jsonify({"error": str(exc)}), 409

def paginate_items(items, limit, offset):
    total = len(items)
    paginated = items[offset : offset + limit]
    return {
        "items": paginated,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": total,
            "hasMore": offset + limit < total
        }
    }

@app.route("/api/data/<collection>", methods=["GET"])
@require_auth_decorator()
def api_data_get(collection):
    user = g.user
    if collection not in STATE_COLLECTION_KEYS:
        return jsonify({"error": "Unknown collection"}), 404
        
    state = resolve_request_state(user)
    items = list(state.get(collection, []))
    
    # Filter
    company_id = request.args.get("companyId", "")
    inquiry_id = request.args.get("inquiryId", "")
    quotation_id = request.args.get("quotationId", "")
    status = request.args.get("status", "").upper()
    
    if company_id:
        items = [item for item in items if str(item.get("companyId")) == company_id]
    if inquiry_id:
        items = [item for item in items if str(item.get("inquiryId")) == inquiry_id]
    if quotation_id:
        items = [item for item in items if str(item.get("quotationId")) == quotation_id]
    if status:
        items = [item for item in items if str(item.get("status")).upper() == status]
        
    requested_limit = int(request.args.get("limit", DEFAULT_PAGE_SIZE))
    requested_offset = max(0, int(request.args.get("offset", 0)))
    limit = min(MAX_PAGE_SIZE, max(1, requested_limit))
    
    if collection not in PAGINATED_COLLECTIONS:
        requested_offset = 0
        limit = max(limit, len(items) or 1)
        
    return jsonify(paginate_items(items, limit, requested_offset))

@app.route("/api/automation/logs", methods=["GET"])
@require_auth_decorator()
def api_automation_logs():
    return jsonify({"logs": communication_logs()})

@app.route("/api/logs", methods=["GET"])
@require_auth_decorator()
def api_system_logs():
    return jsonify({"logs": api_logs()})

@app.route("/api/auth/me", methods=["GET"])
@require_auth_decorator()
def api_auth_me():
    user = g.user
    return jsonify({
        "user": {
            "id": user.get("sub"),
            "name": user.get("name") or user.get("email"),
            "email": user.get("email"),
            "role": user.get("role"),
            "active": True,
        }
    })

@app.route("/api/activities", methods=["GET"])
@require_auth_decorator()
def api_activities():
    return jsonify({"activities": get_activities()})

# Authentication Endpoints
@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    body = request.get_json() or {}
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", "") or "")
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
        
    account = None
    access_token = ""
    refresh_token = ""
    provider_access_token = ""
    provider_refresh_token = ""
    expires_in = int(os.environ.get("ACCESS_TOKEN_TTL_SECONDS", "900"))
    
    client_ip = request.remote_addr

    if supabase_auth_ready():
        auth_payload, error_message, status_code = supabase_password_login(email, password)
        if not auth_payload:
            log_auth(email, f"failed: {error_message}")
            return jsonify({"error": error_message}), status_code if status_code in (400, 401, 403, 422) else 503
        account = build_account_profile({}, email, auth_payload.get("user") or {})
        provider_access_token = str(auth_payload.get("access_token") or "")
        provider_refresh_token = str(auth_payload.get("refresh_token") or "")
        expires_in = int(auth_payload.get("expires_in") or expires_in)
    else:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(q("SELECT id, email, name, role, password_hash, active FROM users WHERE email = ?"), (email,))
            row = cur.fetchone()
        
        if not row:
            log_auth(email, "failed: invalid email")
            return jsonify({"error": "Invalid email or password"}), 401
            
        # Extract fields depending on connection adapter type (dict vs Row)
        if isinstance(row, dict):
            user_id = row["id"]
            u_email = row["email"]
            u_name = row["name"]
            u_role = row["role"]
            pwd_hash = row["password_hash"]
            active = row["active"]
        else:
            user_id, u_email, u_name, u_role, pwd_hash, active = row
            
        if not active or not bcrypt.checkpw(password.encode('utf-8'), pwd_hash.encode('utf-8')):
            log_auth(email, "failed: password verification failed")
            return jsonify({"error": "Invalid email or password"}), 401
            
        clear_login_limit(client_ip)
        account = {
            "id": user_id,
            "email": u_email,
            "name": u_name,
            "role": u_role,
            "active": bool(active)
        }
        
    access_token = issue_access_token(account)
    refresh_token = issue_refresh_token(account)
    log_auth(email, "success")
    return jsonify({
        "user": account,
        "token": access_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
        "auth_provider": "supabase" if supabase_auth_ready() else "local",
        "provider_access_token": provider_access_token,
        "provider_refresh_token": provider_refresh_token,
    })

@app.route("/api/auth/refresh", methods=["POST"])
def api_auth_refresh():
    body = request.get_json() or {}
    refresh_token = str(body.get("refresh_token") or "")
    payload = verify_token(refresh_token, refresh_secret())
    session = REFRESH_SESSIONS.get(refresh_token)
    if not payload or not session or session.get("jti") != payload.get("jti"):
        return jsonify({"error": "Invalid refresh token"}), 401
    account = {
        "id": text_value(payload.get("sub"), max_len=120),
        "name": text_value(payload.get("name"), max_len=120) or text_value(payload.get("email"), max_len=180),
        "email": text_value(payload.get("email"), max_len=180).lower(),
        "role": sanitize_status(payload.get("role"), {"ADMIN", "MANAGER", "SALES", "VIEWER"}, "MANAGER"),
        "active": True,
    }
    access_token = issue_access_token(account)
    return jsonify({"access_token": access_token, "expires_in": int(os.environ.get("ACCESS_TOKEN_TTL_SECONDS", "900"))})

@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    body = request.get_json() or {}
    refresh_token = str(body.get("refresh_token") or "")
    if refresh_token in REFRESH_SESSIONS:
        del REFRESH_SESSIONS[refresh_token]
    return jsonify({"ok": True})

# AI Endpoints
@app.route("/api/ai/assistant", methods=["POST"])
@require_auth_decorator()
def api_ai_assistant():
    body = request.get_json() or {}
    prompt = body.get("prompt", "")
    request_state = body.get("state")
    state = resolve_request_state(g.user, request_state)
    contact_id = str(body.get("contactId") or "")
    answer, provider = call_openai("assistant", prompt, state, contact_id)
    log_ai("assistant", prompt, answer, provider)
    return jsonify({"answer": answer, "provider": provider, "intent": detect_intent(prompt)})

@app.route("/api/ai/email-draft", methods=["POST"])
@require_auth_decorator()
def api_ai_email_draft():
    body = request.get_json() or {}
    prompt = body.get("prompt", "")
    request_state = body.get("state")
    state = resolve_request_state(g.user, request_state)
    contact_id = str(body.get("contactId") or "")
    answer, provider = call_openai("email", prompt, state, contact_id)
    log_ai("email", prompt, answer, provider)
    return jsonify({"answer": answer, "provider": provider, "intent": detect_intent(prompt)})

@app.route("/api/email/send", methods=["POST"])
@require_auth_decorator()
def api_email_send():
    body = request.get_json() or {}
    state = resolve_request_state(g.user, body.get("state"))
    to_email = str(body.get("to") or "").strip()
    subject = str(body.get("subject") or "CRM email").strip()
    content = str(body.get("body") or "").strip()
    linked = str(body.get("linked") or "CRM").strip()
    if not to_email or not content:
        return jsonify({"error": "Email recipient and body are required"}), 400
    try:
        status, provider = send_email_provider(to_email, subject, content)
    except Exception as exc:
        status, provider = "FAILED", "smtp"
        content = f"{content}\n\nDelivery error: {exc}"
    email = add_email_to_state(state, to_email, subject, content, linked, status, provider)
    append_audit(state, "Sent email", linked, "CRM")
    state = sanitize_crm_state(state, g.user)
    save_state(state, state_scope_for_user(g.user))
    log_communication("EMAIL", "OUT", to_email, subject, content, status, provider, linked)
    return jsonify({"state": state, "email": email, "status": status, "provider": provider})

@app.route("/api/whatsapp/send", methods=["POST"])
@require_auth_decorator()
def api_whatsapp_send():
    body = request.get_json() or {}
    state = resolve_request_state(g.user, body.get("state"))
    contact_id = str(body.get("contactId") or "").strip()
    to_phone = str(body.get("to") or "").strip()
    content = str(body.get("content") or "").strip()
    linked = str(body.get("linked") or "CRM").strip()
    if not to_phone and contact_id:
        contact = find_contact(state, contact_id)
        to_phone = contact.get("whatsapp") or contact.get("phone", "")
    if not to_phone or not content:
        return jsonify({"error": "WhatsApp recipient and content are required"}), 400
    try:
        status, provider = send_whatsapp_provider(to_phone, content)
    except Exception as exc:
        status, provider = "FAILED", "meta"
        content = f"{content}\n\nDelivery error: {exc}"
    message = add_whatsapp_to_state(state, contact_id, to_phone, content, "OUT", bool(body.get("bot")), status, provider)
    append_audit(state, "Sent WhatsApp message", linked, "CRM")
    state = sanitize_crm_state(state, g.user)
    save_state(state, state_scope_for_user(g.user))
    log_communication("WHATSAPP", "OUT", to_phone, "", content, status, provider, linked)
    return jsonify({"state": state, "message": message, "status": status, "provider": provider})

@app.route("/api/whatsapp/inbound", methods=["POST"])
@require_auth_decorator()
def api_whatsapp_inbound():
    body = request.get_json() or {}
    state = resolve_request_state(g.user, body.get("state"))
    contact_id = str(body.get("contactId") or "").strip()
    content = str(body.get("content") or "").strip()
    if not contact_id or not content:
        return jsonify({"error": "Contact and content are required"}), 400
    contact = find_contact(state, contact_id)
    phone = contact.get("whatsapp") or contact.get("phone", "")
    inbound = add_whatsapp_to_state(state, contact_id, phone, content, "IN", False, "RECEIVED", "webhook")
    log_communication("WHATSAPP", "IN", phone, "", content, "RECEIVED", "webhook", contact_id)
    reply = None
    if body.get("autoReply", True):
        answer, provider = call_openai("whatsapp", f"Write a concise WhatsApp reply to: {content}", state, contact_id)
        reply_text = answer[:900]
        status, wa_provider = send_whatsapp_provider(phone, reply_text)
        reply = add_whatsapp_to_state(state, contact_id, phone, reply_text, "OUT", True, status, wa_provider if wa_provider != "simulated" else provider)
        log_communication("WHATSAPP", "OUT", phone, "", reply_text, status, wa_provider, contact_id)
    append_audit(state, "Received WhatsApp message", contact_id, "Webhook")
    state = sanitize_crm_state(state, g.user)
    save_state(state, state_scope_for_user(g.user))
    return jsonify({"state": state, "message": inbound, "reply": reply})

@app.route("/api/automation/run", methods=["POST"])
@require_auth_decorator()
def api_automation_run():
    body = request.get_json() or {}
    state = resolve_request_state(g.user, body.get("state"))
    state, results = run_automation(state, state_scope_for_user(g.user))
    state = sanitize_crm_state(state, g.user)
    save_state(state, state_scope_for_user(g.user))
    return jsonify({"state": state, "results": results, "count": len(results), "logs": communication_logs()})

@app.route("/api/generate-message", methods=["POST"])
@require_auth_decorator()
def api_generate_message():
    body = request.get_json() or {}
    lead_id = str(body.get("leadId") or body.get("lead_id") or "LEAD")
    prompt = str(body.get("prompt") or f"Draft follow-up message for lead {lead_id}")
    request_state = body.get("state")
    state = resolve_request_state(g.user, request_state)
    answer, provider, cached, reason = generate_message_safe(lead_id, prompt, state, g.user.get("sub"), "assistant")
    log_ai("generate-message", prompt, answer, provider)
    create_activity(lead_id, "AI_MESSAGE_GENERATED", "SUCCESS" if provider != "fallback" else "FALLBACK", f"Provider={provider}", {"cached": cached, "reason": reason})
    return jsonify({"message": answer, "provider": provider, "cached": cached, "fallback_reason": reason})

@app.route("/api/send-email", methods=["POST"])
@require_auth_decorator()
def api_send_email_v2():
    body = request.get_json() or {}
    lead_id = str(body.get("leadId") or body.get("lead_id") or "LEAD")
    to_email = str(body.get("to") or "").strip()
    subject = str(body.get("subject") or "Follow-up from JK Fluid Controls").strip()
    message = str(body.get("message") or body.get("body") or "").strip()
    if not to_email or not message:
        return jsonify({"error": "Email recipient and message are required"}), 400
    status, provider = send_email_provider(to_email, subject, message)
    create_activity(lead_id, "EMAIL_SENT", status, f"to={to_email}", {"provider": provider, "subject": subject})
    mark_lead_contacted(lead_id, follow_up_sent=False)
    return jsonify({"ok": status in ("SENT", "SIMULATED"), "status": status, "provider": provider})

@app.route("/api/send-whatsapp", methods=["POST"])
@require_auth_decorator()
def api_send_whatsapp_v2():
    body = request.get_json() or {}
    lead_id = str(body.get("leadId") or body.get("lead_id") or "LEAD")
    to_phone = str(body.get("to") or "").strip()
    message = str(body.get("message") or body.get("content") or "").strip()
    if not to_phone or not message:
        return jsonify({"error": "WhatsApp recipient and message are required"}), 400
    status, provider = send_whatsapp_provider(to_phone, message)
    create_activity(lead_id, "WHATSAPP_SENT", status, f"to={to_phone}", {"provider": provider})
    mark_lead_contacted(lead_id, follow_up_sent=False)
    return jsonify({"ok": status in ("SENT", "DELIVERED"), "status": status, "provider": provider})

@app.route("/lead/<lead_id>/contacted", methods=["PATCH"])
@app.route("/api/lead/<lead_id>/contacted", methods=["PATCH"])
@require_auth_decorator()
def handle_lead_contacted_route(lead_id):
    body = request.get_json() or {}
    follow_up_sent = bool(body.get("follow_up_sent", False))
    mark_lead_contacted(lead_id, follow_up_sent=follow_up_sent)
    create_activity(lead_id, "LEAD_CONTACT_UPDATED", "SUCCESS", "Lead contact fields updated", {"follow_up_sent": follow_up_sent})
    return jsonify({"ok": True, "lead_id": lead_id, "follow_up_sent": follow_up_sent})

# --- GRANULAR REST ENDPOINTS FOR ENTITIES ---

# 1. Companies REST
@app.route("/api/companies", methods=["GET", "POST"])
@require_auth_decorator()
def handle_companies():
    user = g.user
    if request.method == "GET":
        items = load_relational_collection("companies", user)
        res = [to_camel_case(item, "companies") for item in items]
        return jsonify(res)
    elif request.method == "POST":
        try:
            body = request.get_json() or {}
            res = insert_db_row("companies", body, user)
            return jsonify(res), 201
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route("/api/companies/<id>", methods=["PATCH", "DELETE"])
@require_auth_decorator()
def handle_company_detail(id):
    user = g.user
    if request.method == "PATCH":
        try:
            body = request.get_json() or {}
            res = update_db_row("companies", id, body, user)
            return jsonify(res)
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except ConflictError as e:
            return jsonify({"error": str(e)}), 409
        except ValueError as e:
            return jsonify({"error": str(e)}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    elif request.method == "DELETE":
        try:
            delete_db_row("companies", id, user)
            return jsonify({"success": True})
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400

# 2. Contacts REST
@app.route("/api/contacts", methods=["GET", "POST"])
@require_auth_decorator()
def handle_contacts():
    user = g.user
    if request.method == "GET":
        items = load_relational_collection("contacts", user)
        res = [to_camel_case(item, "contacts") for item in items]
        return jsonify(res)
    elif request.method == "POST":
        try:
            body = request.get_json() or {}
            res = insert_db_row("contacts", body, user)
            return jsonify(res), 201
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route("/api/contacts/<id>", methods=["PATCH", "DELETE"])
@require_auth_decorator()
def handle_contact_detail(id):
    user = g.user
    if request.method == "PATCH":
        try:
            body = request.get_json() or {}
            res = update_db_row("contacts", id, body, user)
            return jsonify(res)
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except ConflictError as e:
            return jsonify({"error": str(e)}), 409
        except ValueError as e:
            return jsonify({"error": str(e)}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    elif request.method == "DELETE":
        try:
            delete_db_row("contacts", id, user)
            return jsonify({"success": True})
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400

# 3. Inquiries/Leads REST
@app.route("/api/leads", methods=["GET", "POST"])
@app.route("/api/inquiries", methods=["GET", "POST"])
@require_auth_decorator()
def handle_inquiries():
    user = g.user
    if request.method == "GET":
        items = load_relational_collection("inquiries", user)
        res = [to_camel_case(item, "inquiries") for item in items]
        return jsonify(res)
    elif request.method == "POST":
        try:
            body = request.get_json() or {}
            res = insert_db_row("inquiries", body, user)
            return jsonify(res), 201
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route("/api/leads/<id>", methods=["PATCH", "DELETE"])
@app.route("/api/inquiries/<id>", methods=["PATCH", "DELETE"])
@require_auth_decorator()
def handle_inquiry_detail(id):
    user = g.user
    if request.method == "PATCH":
        try:
            body = request.get_json() or {}
            res = update_db_row("inquiries", id, body, user)
            return jsonify(res)
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except ConflictError as e:
            return jsonify({"error": str(e)}), 409
        except ValueError as e:
            return jsonify({"error": str(e)}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    elif request.method == "DELETE":
        try:
            delete_db_row("inquiries", id, user)
            return jsonify({"success": True})
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400

# 4. Quotations REST
@app.route("/api/quotations", methods=["GET", "POST"])
@require_auth_decorator()
def handle_quotations():
    user = g.user
    if request.method == "GET":
        items = load_relational_collection("quotations", user)
        res = [to_camel_case(item, "quotations") for item in items]
        return jsonify(res)
    elif request.method == "POST":
        try:
            body = request.get_json() or {}
            res = insert_db_row("quotations", body, user)
            return jsonify(res), 201
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route("/api/quotations/<id>", methods=["PATCH", "DELETE"])
@require_auth_decorator()
def handle_quotation_detail(id):
    user = g.user
    if request.method == "PATCH":
        try:
            body = request.get_json() or {}
            res = update_db_row("quotations", id, body, user)
            return jsonify(res)
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except ConflictError as e:
            return jsonify({"error": str(e)}), 409
        except ValueError as e:
            return jsonify({"error": str(e)}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    elif request.method == "DELETE":
        try:
            delete_db_row("quotations", id, user)
            return jsonify({"success": True})
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400

# 5. Orders REST
@app.route("/api/orders", methods=["GET", "POST"])
@require_auth_decorator()
def handle_orders():
    user = g.user
    if request.method == "GET":
        items = load_relational_collection("orders", user)
        res = [to_camel_case(item, "orders") for item in items]
        return jsonify(res)
    elif request.method == "POST":
        try:
            body = request.get_json() or {}
            res = insert_db_row("orders", body, user)
            return jsonify(res), 201
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route("/api/orders/<id>", methods=["PATCH", "DELETE"])
@require_auth_decorator()
def handle_order_detail(id):
    user = g.user
    if request.method == "PATCH":
        try:
            body = request.get_json() or {}
            res = update_db_row("orders", id, body, user)
            return jsonify(res)
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except ConflictError as e:
            return jsonify({"error": str(e)}), 409
        except ValueError as e:
            return jsonify({"error": str(e)}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    elif request.method == "DELETE":
        try:
            delete_db_row("orders", id, user)
            return jsonify({"success": True})
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400

# Static File Catch-All Route
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_static(path):
    root = static_root()
    if path and (root / path).exists() and not (root / path).is_dir():
        return send_from_directory(str(root), path)
    return send_from_directory(str(root), "index.html")

def call_openai(kind, prompt, state, contact_id=""):
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return fallback_ai(kind, prompt, state), "fallback"

    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    intent = detect_intent(prompt)
    system_msg = (
        "You are the JK Fluid Controls CRM assistant for industrial valves, actuators, and process equipment. "
        "Use only the CRM context provided. Be concise, accurate, and sales-operations focused. "
        "For WhatsApp replies, keep the response under 80 words, professional, and action oriented. "
        "If the customer asks for price or quote, request size, pressure rating, body material, quantity, media, and delivery date when missing. "
        "If the customer asks for order or delivery status, refer to available order/dispatch context and say a sales executive will confirm if details are incomplete. "
        "Do not invent prices, commitments, dispatch dates, certifications, or stock."
    )
    user_prompt = (
        f"CRM summary:\n{crm_summary(state)}\n\n"
        f"Contact context:\n{contact_context(state, contact_id) if contact_id else 'No specific contact selected.'}\n\n"
        f"Detected intent: {intent}\n\n"
        f"User request:\n{prompt}"
    )
    body = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": 700,
            "temperature": 0.3,
        }
    ).encode("utf-8")
    request_obj = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=body,
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    ssl_context = None
    if str(os.environ.get("OPENAI_INSECURE_TLS", "false")).strip().lower() in ("1", "true", "yes", "on"):
        ssl_context = ssl._create_unverified_context()
    elif certifi:
        ssl_context = ssl.create_default_context(cafile=certifi.where())
    delays = [2, 4, 8]
    for attempt, delay in enumerate(delays, start=1):
        try:
            with urllib.request.urlopen(request_obj, timeout=25, context=ssl_context) as response:
                payload = json.loads(response.read().decode("utf-8"))
            text = extract_openai_text(payload)
            if text:
                return text, "openai"
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                app_log("OpenAI quota/rate-limit exceeded", attempt=attempt, level=logging.WARNING)
            else:
                app_log("OpenAI HTTP error", attempt=attempt, error=str(exc), level=logging.ERROR)
            if attempt < len(delays):
                time.sleep(delay)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            app_log("OpenAI request failed", attempt=attempt, error=str(exc), level=logging.ERROR)
            if attempt < len(delays):
                time.sleep(delay)
    
    return fallback_ai(kind, f"{prompt}\n\nProvider error after retries.", state), "fallback"

def main():
    load_env()
    
    # Enforce secrets configuration
    try:
        auth_secret()
        refresh_secret()
    except RuntimeError as e:
        app_log(str(e), level=logging.CRITICAL)
        sys.exit(1)
        
    # Enforce Supabase/Postgres connection validation in production mode
    if not validate_supabase_url():
        app_log("Supabase validation failed. Aborting startup.", level=logging.CRITICAL)
        sys.exit(1)
        
    try:
        init_db()
    except Exception as exc:
        app_log("Database init failed", engine=db_engine(), error=str(exc), level=logging.CRITICAL)
        raise

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8766"))
    
    scheduler_thread = threading.Thread(target=followup_scheduler_loop, daemon=True)
    scheduler_thread.start()
    
    app_log(f"Starting native Flask production server on {host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)

if __name__ == "__main__":
    main()
