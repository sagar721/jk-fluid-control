# Industrial Business CRM Prototype

A local CRM prototype for an industrial business workflow, built from a product requirements document. It includes customer and inquiry tracking, quotations, order/dispatch workflows, messaging integrations, automation, and AI-assisted CRM features.

**Live demo:** https://jk-fluid-control.vercel.app  
**Project status:** Working prototype. External integrations require valid credentials; without them, supported messaging/AI workflows can use simulated or local fallback behavior.

> The client's business name is intentionally omitted from this public README until permission to identify the business is confirmed.

## My contribution

I developed the CRM prototype, including the frontend, Python backend and REST endpoints, database integration, role-based access, communication/AI integrations, test harness, and deployment configuration.

The original requirements document specified React, Express, and PostgreSQL. This implementation uses a JavaScript/HTML/CSS frontend and a Flask backend, with SQLite as the local default and optional PostgreSQL/Supabase configuration.

## Features

- **Access:** demo login roles for Admin, Sales Manager, Sales Executive, and Viewer, with role-based navigation.
- **Sales pipeline:** companies, contacts, inquiries, and a pipeline board.
- **Quotations:** quotation builder with GST calculations and printable quotations.
- **Fulfilment:** orders, dispatch tracking, activities, and calendar views.
- **Insights:** dashboard KPIs, charts, activity feed, and reports with CSV export.
- **Messaging:** email and WhatsApp inbox/logging flows, with SMTP and WhatsApp provider configuration.
- **Automation:** follow-up workflows for quotation, inquiry, and delivery-feedback events; scheduler interval is configurable.
- **AI assistant:** OpenAI-backed CRM assistance when configured, with deterministic local fallback behavior.
- **Administration:** settings, users, templates, audit log, and dark mode.

External messaging and AI providers are not active until valid credentials and provider-side configuration are supplied. Simulated delivery is not the same as a real email or WhatsApp send.

## Architecture

```text
Browser (index.html, app.js, styles.css; build output in dist/)
        |
        | REST requests
        v
Flask backend (server.py; wsgi.py for Gunicorn)
  ├── Authentication and role-based access
  ├── CRM endpoints
  ├── SQLite by default; optional PostgreSQL/Supabase
  ├── SMTP / WhatsApp provider integrations
  └── Follow-up scheduler
```

**Tech stack:** Python, Flask, Gunicorn, SQLite, PostgreSQL/Supabase, psycopg, bcrypt, JavaScript, HTML, CSS, Docker, Nginx, Vercel, and Render.

## Getting started locally

### Requirements

- Python 3.10 or newer recommended
- Node.js and npm for the frontend build script

Clone the repository and start the app:

```bash
git clone https://github.com/sagar721/jk-fluid-control.git
cd jk-fluid-control
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
npm install
npm run build
python3 server.py
```

Open http://127.0.0.1:8765 in your browser. If you edit `.env`, keep real credentials local and never commit the file.

### Demo login

When Supabase Auth is not configured, the app supports demo-mode accounts. The default demo password is controlled by `DEMO_LOGIN_PASSWORD` in `.env`; change it before sharing a running instance.

| Email | Role |
|---|---|
| `admin@jkfluidcontrols.com` | Admin |
| `manager@jkfluidcontrols.com` | Sales Manager |
| `sales@jkfluidcontrols.com` | Sales Executive |
| `viewer@jkfluidcontrols.com` | Viewer |

These are demo account identifiers, not real customer accounts. Do not use the demo configuration as production authentication.

## Configuration

Copy `.env.example` to `.env` and set only the values needed for your environment.

| Variable | Purpose |
|---|---|
| `HOST`, `PORT` | Server bind address and port |
| `DATABASE_URL` or `SUPABASE_DB_URL` | Optional PostgreSQL/Supabase database connection |
| `SQLITE_DB_PATH` | Optional SQLite database file path |
| `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET` | Required by the Gunicorn/production entry point; use strong generated secrets |
| `SUPABASE_URL`, `SUPABASE_ANON_KEY` | Supabase client configuration |
| `SUPABASE_SERVICE_ROLE_KEY` | Server-side Supabase key only; never expose it in browser code |
| `DEMO_LOGIN_PASSWORD` | Password for local demo-mode accounts |
| `OPENAI_API_KEY`, `OPENAI_MODEL`, `OPENAI_TIMEOUT_SECONDS` | Optional AI integration |
| `AI_SESSION_LIMIT`, `AI_SESSION_WINDOW_SECONDS` | AI usage limits |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` | Optional email delivery configuration |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_WHATSAPP_FROM` | Optional Twilio WhatsApp integration |
| Meta WhatsApp settings | Optional WhatsApp Cloud API integration |

Generate JWT secrets with:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

For Gmail SMTP, use a Google App Password rather than your normal account password. Keep all secrets in local `.env` files or the hosting provider's secret settings.

## Supabase schema and example client

The Supabase schema and setup notes are available in:

- [Supabase backend guide](supabase/README.md)
- [CRM backend migration](supabase/migrations/20260425213000_crm_backend.sql)
- [Supabase JavaScript example](supabase/examples/crm-client.mjs)

The schema documents Supabase Auth, CRM tables, row-level security policies, and ownership-aware relationships. Review the schema and policies in your own Supabase project before using it with real customer data.

## Tests and checks

Start the local server in one terminal, then run the system test harness in another:

```bash
python3 test_system.py
```

You can also run the repository's syntax checks:

```bash
npm run check
```

Record test results with the environment and date when publishing them; results from one local run do not guarantee production readiness.

## Deployment notes

The repository includes a Gunicorn-compatible `wsgi.py` entry point. The production entry point requires JWT access/refresh secrets and a valid PostgreSQL/Supabase database configuration. Set these as server-side environment variables in the hosting provider. Do not expose service-role keys or JWT secrets in frontend variables.

The live demo is available at https://jk-fluid-control.vercel.app. Availability may change, and external services may behave differently without their credentials.

## Known limitations

- This is a working prototype, not a claim of production readiness or a security audit.
- Provider integrations need valid credentials and provider-side setup; simulated messages are not delivered messages.
- SQLite is intended for local use. Configure and validate PostgreSQL/Supabase before deploying a shared production instance.
- The requirements document and this implementation use different frontend/backend stacks.
- Confirm business-name permission before identifying the client publicly.
