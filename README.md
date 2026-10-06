# CloudShield

Adaptive cloud threat detection and explainable risk scoring, built in four stages. See [project.md](project.md) for the full specification.

## Current build: Stage 1 — Foundation

Implemented: Flask application factory, SQLite migrations, password-hashed local accounts, CSRF-protected login/logout, server-side administrator checks, structured event collection, an administrator event viewer, and paginated event APIs.

Next: Stage 2 detection rules. Risk scores, decay, incidents, blocks, charts, and AWS deployment will follow in later stages.

## Run locally on Windows

Tested with Python 3.14.4. Run these commands in the project directory using PowerShell. Calling the virtual environment's Python directly avoids PowerShell activation-policy changes.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
```

Put the generated value in `.env` as `CLOUDSHIELD_SECRET_KEY`. Keep `.env` private. If `.env` already exists, retain it instead of copying over it. A local `.env` was generated during the initial build; existing workspace users can proceed to database setup.

```powershell
.\.venv\Scripts\python.exe -m flask --app app init-db
.\.venv\Scripts\python.exe -m flask --app app create-user --username admin --role admin
.\.venv\Scripts\python.exe -m flask --app app create-user --username demo --role user
.\.venv\Scripts\python.exe -m flask --app app run --host 127.0.0.1 --port 5000
```

Each `create-user` command prompts for a password and confirmation. Use 12-256 characters. There are no default accounts or passwords. Existing usernames are never overwritten. Open **http://127.0.0.1:5000**. Stop the server with `Ctrl+C`.

`init-db` applies pending SQL migrations without deleting users or events. The database is stored in `instance/cloudshield.sqlite3`, which is excluded from Git. Run migrations before serving requests and with only one migration process active. The local Flask server is for development; production hosting is a later stage.

## Verify the foundation

1. Sign in as `demo`, visit the workspace, and refresh it.
2. Open the administrator area. The ordinary user should receive HTTP 403.
3. Sign out and submit an incorrect password to generate a failed-login event.
4. Sign in as `admin` and open **Event log**. Confirm successful logins, failed logins, page requests, and access denials are visible.
5. Sign out and verify administrator APIs require authentication.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The tests use isolated temporary databases and exercise actual forms with CSRF enabled. They cover account hashing, migration preservation, login/logout, anonymous failure attribution, administrator authorization, sanitization, source-IP handling, pagination, session role changes, and configuration guards.

## Routes

| Route | Access | Behavior |
| --- | --- | --- |
| `GET /` | Signed-in user | Demo application workspace |
| `GET, POST /auth/login` | Public, CSRF required for POST | Sign-in form and authentication |
| `POST /auth/logout` | Signed-in user, CSRF required | End session |
| `GET /admin` | Administrator | Event viewer with pagination |
| `GET /api/events?page=1&per_page=25` | Administrator | Event records, maximum 100 per page |
| `GET /api/overview` | Administrator | Total and per-type event counts |
| `GET /health` | Public | Minimal process health response |

Anonymous HTML requests redirect to login; anonymous API requests receive 401. Authenticated ordinary users receive 403 for administrator resources.

## Collection behavior

Each completed non-static, non-health request produces one event with a generated request ID, UTC timestamp, event type, source IP, authenticated user if known, route template, method, status, and allowlisted metadata. Authentication and authorization outcomes replace the generic event type for that request. Failed logins are not assigned to the submitted username.

Passwords, query strings, raw paths for unmatched routes, request bodies, cookies, and arbitrary headers are not stored. Forwarding headers are ignored; source IP comes from the direct connection. Trusted proxy handling must be explicitly configured when adding a deployment proxy.

Administrator views and API requests are logged but marked ineligible for the future request-rate detector. Counts describe completed requests before the current dashboard request finishes. Refresh to see the latest completed request. `/health` checks process responsiveness only, not database readiness.

SQLite access follows the [Flask request-scoped connection pattern](https://flask.palletsprojects.com/en/stable/tutorial/database/). Forms use global [Flask-WTF CSRF protection](https://flask-wtf.readthedocs.io/en/1.2.x/csrf/).

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `CLOUDSHIELD_SECRET_KEY` | Required | Random signing secret of at least 32 characters |
| `CLOUDSHIELD_ENV` | `development` | Set `production` for secure-cookie enforcement |
| `CLOUDSHIELD_COOKIE_SECURE` | False locally, true in production | Send session cookies only over HTTPS |
| `CLOUDSHIELD_DATABASE` | `instance/cloudshield.sqlite3` | Optional absolute database file path |

Sessions use HttpOnly and SameSite=Lax cookies with a one-hour lifetime. Production mode refuses insecure session cookies. The application adds a restrictive content security policy and disables caching for application responses.

## Layout

```text
app/
  __init__.py       Application factory and error handlers
  config.py         Environment configuration
  db.py             Connections and migration command
  models.py         User and event persistence
  auth/             Authentication, role checks, account CLI
  collection/       Sanitized request event capture
  routes.py         Workspace, administrator views and APIs
  templates/        HTML pages
  static/           Stylesheet
migrations/         Versioned SQL schema changes
tests/              Foundation integration tests
```
