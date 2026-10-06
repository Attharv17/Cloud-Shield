# CloudShield

Adaptive cloud threat detection and explainable risk scoring, built in four stages. See [project.md](project.md) for the full specification.

## Current build: Stage 4 — Dashboard and demonstration — Risk, incidents and responses

Implemented: the Flask/SQLite foundation, four detection rules, evidence-linked findings, source history, bounded risk scores with an audit ledger, scheduled decay, incident timelines, alerts, temporary block enforcement, and administrator recovery. Administrator pages and APIs expose each layer.

Next: Stage 4 dashboard charts, demonstration polish, and deployment preparation. CAPTCHA remains a recommendation; email, WAF and IAM integrations are not implemented.

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

The tests use isolated temporary databases and exercise actual forms with CSRF enabled. They cover authentication, migration preservation, authorization, sanitization, detection, scoring, decay, incident grouping, block lifecycle, recovery and concurrency. Pytest uses `.pytest-tmp/` in this workspace (cleared on each run) and `.test-runs/cache/`, avoiding shared Windows temporary-directory permissions.

## Upgrade from an earlier stage

Stop the development server, apply the additive migration, and restart it:

```powershell
.\.venv\Scripts\python.exe -m flask --app app init-db
.\.venv\Scripts\python.exe -m flask --app app run --host 127.0.0.1 --port 5000
```

Migration `002_detection.sql` adds configuration snapshots, evaluation markers, findings, evidence links, and source histories. It preserves existing users and events. Historical Stage 1 events are not automatically evaluated or included in new detection windows.

Migration `003_risk_response.sql` adds risk entities, versioned policies, the score ledger, incidents, alerts and action audits. Historical Stage 2 findings remain visible but are not retroactively scored. Only newly evaluated events enter the Stage 3 pipeline. Existing accounts and history are preserved.

## Run risk maintenance

Run this worker in a second terminal while the application is running:

```powershell
.\.venv\Scripts\python.exe -m flask --app app risk-worker --interval 10
```

It applies decay, closes quiet incidents and expires or renews blocks without incoming requests. Stop with `Ctrl+C`. To run once, use:

```powershell
.\.venv\Scripts\python.exe -m flask --app app risk-maintain
```

The worker must be started explicitly; the Flask server does not spawn a background process. Non-static application requests also perform catch-up maintenance before enforcement. SQLite write transactions coordinate requests and workers; duplicate workers cannot apply the same decay twice. After downtime, the next run applies all complete elapsed intervals. The worker processes the small prototype database synchronously; a supervised service and scaling work belong to deployment.

## Risk scoring and response policy

Each finding updates its source IP and, when verified, its associated user by the configured weight. Separate ledgers explain both records. The effective response uses the **higher** score, never their sum. Anonymous failed logins affect only their IP. A successful login from a new context can affect both the verified user and that source IP.

| Score | Severity | Response |
| --- | --- | --- |
| 0-24 | Low | Allow and log |
| 25-49 | Medium | Monitor; recommend CAPTCHA |
| 50-74 | High | Administrator alert |
| 75-100 | Critical | Administrator alert and a 5-minute application block |

Scores stay between 0 and 100. Each ledger record includes the requested and applied change, before/after scores, time, reason, policy version, and finding/event reference when applicable. For example, a +25 finding at 90 records a requested +25 and an applied +10. Alerts are created on escalation into high or critical, not on every subsequent request or downward severity change.

- **Decay:** subtract 10 for each complete 5-minute quiet interval. Persisted anchors and atomic updates prevent duplicate decay. Failed logins and unauthorized restricted requests reset the quiet interval even when a finding cooldown suppresses another weight. Ongoing above-threshold request traffic also resets it.
- **Normal activity:** subtract 5 for successful eligible application activity after 5 minutes without suspicious activity, at most once per entity per 5 minutes. Administrator polling and rejected requests never earn this reduction. Decay and a normal reduction can both apply when independently eligible.
- **Blocks:** the triggering request can complete; subsequent application requests receive HTTP 429 with `Retry-After` and the current expiry. Both IP and logged-in-user blocks are enforced. A blocked user may authenticate from a new IP, but subsequent authenticated application access remains blocked. Static assets and process health remain accessible.
- **Expiry:** a block stays active until its expiry even if the score falls earlier. At expiry, maintenance first applies due decay, then releases the block if risk is below critical or creates a new block if risk remains critical. Rejected traffic is logged without findings, score increases, quiet-period resets or early expiry extensions.
- **Clock handling:** persisted UTC processing time never moves backward when the host clock does. Keep the deployment host's clock synchronized.

Defaults live in `app/risk/policy.json`. For overrides, copy it to `instance/risk-policy.json`, set `CLOUDSHIELD_RISK_POLICY_FILE` to its absolute path, and restart both server and worker with the same configuration. Policy values are validated and fingerprinted; historical ledger entries and block actions retain their original policy versions. Updated decay settings apply to elapsed time since each persisted anchor; configuration changes do not rewrite history.

## Incidents, alerts and recovery

Open **Risk & incidents** as an administrator. Select an entity for its complete score history and block records, or an incident for its event, score, alert and action timeline. Incidents group findings by IP and stay open until 10 minutes without another finding. The first finding links the preceding minute of context plus all supporting evidence. Subsequent activity from that IP is linked while the incident is open. Known users are associated through verified events; usernames in failed login submissions never merge incidents.

Incident closure and block expiry are independent. Peak risk is retained; current risk is the highest current score among associated entities and can change after closure. Score changes are linked to associated open incidents, while the entity ledger retains its full history. Alert acknowledgement requires administrator authentication and CSRF protection and records the actor and timestamp.

An accidental demo block can affect an administrator sharing the same IP. Use the local recovery command, which remains available independently of HTTP enforcement:

```powershell
.\.venv\Scripts\python.exe -m flask --app app recover-entity --entity-id 1 --admin-username admin --reason "Reset controlled demonstration"
```

Enter the administrator password when prompted. Recovery resets that entity to zero and revokes its active blocks with an audit reason and actor. It does not erase findings, incidents or history. If both a user and an IP are blocked, inspect and recover both entity IDs as appropriate. The command rejects ordinary-user credentials.

## Verify detection

After creating an ordinary account such as `demo`, run:

```powershell
.\.venv\Scripts\python.exe -m flask --app app demo-traffic --username demo
```

Enter that account's password when prompted. The command uses Flask's internal request client against the configured development application and database; no running server or network target is needed. It sends a baseline login, failed logins, a denied administrator request, a page-request burst, and a login from a new browser marker. Simulated requests use documentation address `192.0.2.10` and respect CSRF protection. No account is created or reset, and the password is not logged.

The command is development-only, rejects administrator credentials, and caps scenarios at 25 failed logins and 201 page requests (plus bounded login-form and setup requests). Existing cooldowns can suppress repeat findings, and existing blocks can stop a scenario. Sign in as an administrator and open **Findings** or **Risk & incidents** to inspect the results. The generator adds persistent demo records; it does not clear existing data. A fresh default run produces 70 IP risk (20 + 25 + 15 + 10), below the critical threshold.

For the full response demonstration, generate another eligible suspicious burst after its cooldown. Verify the score crosses 75, the next request is blocked, the ledger explains the change, and the running worker eventually decays risk below critical and releases the block at expiry. Repeated attempts during a block must not keep adding risk. Use a separate administrator source or the recovery command if the demonstration blocks your browser.

Tests additionally cover exact rule boundaries, rolling-window expiry, IP isolation, cooldown expiry, duplicate retries, concurrent requests, transactional rollback, configuration validation, restart persistence, source baselines, marker tampering, findings authorization, and the bounded demo.

## Detection policy

| Rule | Trigger | Weight | Repeat control |
| --- | --- | --- | --- |
| Failed-login burst | At least 5 failures from an IP in 60 seconds | +20 | Once per IP per 60 seconds |
| High request frequency | More than 100 eligible requests from an IP in 60 seconds | +15 | Once per IP per 60 seconds |
| Restricted access | Unauthorized request to an administrator HTML or API route | +25 | Once per IP per 60 seconds |
| New source context | Successful login with a previously unseen IP or signed browser marker | +10 | Once per newly learned context; combine IP and marker novelty |

The rolling window is `(evaluation time - window, evaluation time]`. The engine uses UTC processing time after taking the SQLite write lock, so request completion order, concurrency, and slow login hashing do not create partially evaluated windows. Original event timestamps remain available in the evidence. Clock rollback is clamped to the latest evaluation time. At exactly the cooldown boundary, a new eligible event may produce a finding if its current window still meets the threshold.

Event insertion, evaluation, findings, evidence, and source-history updates commit together. Request IDs and per-event evaluation records prevent duplicate processing, even after configuration changes or restarts. Cooldowns also persist across restarts and configuration changes. A failed transaction rolls back the event and its findings together; it must not be treated as successful telemetry collection.

Ordinary anonymous redirects to the workspace login are recorded as access denials but do not trigger the restricted-access rule. Authorized administrator requests do not trigger that rule. Static assets, health checks, dashboard pages, and administrator APIs do not contribute to request-rate detection; denied administrator requests still qualify for restricted-access detection.

The first successful login establishes an IP and browser-marker baseline for each user without a finding. Later successful logins learn newly seen contexts and produce a single finding when either or both are unfamiliar. Known IPs and markers are remembered separately, so a new pairing of two already known values is not automatically suspicious. Failed authentication never establishes history for the submitted username.

The browser marker is a signed, HttpOnly, SameSite=Lax cookie, independent of the login session. Only its keyed fingerprint is stored on successful-login events. Clearing the cookie, using a different browser, or changing the signing secret can look like a new browser. This is an explainable contextual signal, not reliable device identity or an authentication factor.

### Configure rules

Defaults live in `app/detection/rules.json`. To override them, copy that file to `instance/rules.json`, set `CLOUDSHIELD_RULES_FILE` to the absolute path in `.env`, edit the values, and restart the app. The four rule names and their fields are fixed; integer thresholds, windows, cooldowns, and weights are validated at startup. Unknown fields and invalid values stop startup with a configuration error.

Each canonical configuration receives a SHA-256 version, and its snapshot is persisted when first used. Findings keep their original version and weight after later configuration changes. `/api/settings` shows the active rules to administrators; individual findings include the historical configuration that produced them.

Findings counts, triggering-event counts, and distinct evidence-event counts are separate metrics: one event can trigger multiple rules, and a burst finding can reference many supporting events.

## Routes

| Route | Access | Behavior |
| --- | --- | --- |
| `GET /` | Signed-in user | Demo application workspace |
| `GET, POST /auth/login` | Public, CSRF required for POST | Sign-in form and authentication |
| `POST /auth/logout` | Signed-in user, CSRF required | End session |
| `GET /admin` | Administrator | Event viewer with pagination |
| `GET /api/events?page=1&per_page=25` | Administrator | Event records, maximum 100 per page |
| `GET /api/overview` | Administrator | Total and per-type event counts |
| `GET /admin/findings` | Administrator | Paginated findings viewer |
| `GET /admin/findings/<id>` | Administrator | Explanation and supporting events |
| `GET /api/findings?page=1&per_page=25` | Administrator | Findings and distinct event counts |
| `GET /api/findings/<id>` | Administrator | Finding, evidence, historical configuration |
| `GET /api/settings` | Administrator | Active detection configuration |
| `GET /admin/risk` | Administrator | Risk, incidents, alerts and acknowledgement forms |
| `GET /admin/entities/<id>` | Administrator | Entity score ledger and blocks |
| `GET /admin/incidents/<id>` | Administrator | Incident timeline |
| `GET /api/entities`, `GET /api/entities/<id>` | Administrator | Paginated entities / full detail |
| `GET /api/incidents`, `GET /api/incidents/<id>` | Administrator | Paginated incidents / full detail |
| `GET /api/alerts` | Administrator | Paginated alerts |
| `POST /api/alerts/<id>/acknowledge` | Administrator, CSRF required | Audited, idempotent acknowledgement |
| `GET /health` | Public | Minimal process health response |

Anonymous HTML requests redirect to login; anonymous API requests receive 401. Authenticated ordinary users receive 403 for administrator resources.

## Collection behavior

Each completed non-static, non-health request produces one event with a generated request ID, UTC timestamp, event type, source IP, authenticated user if known, route template, method, status, and allowlisted metadata. Authentication and authorization outcomes replace the generic event type for that request. Failed logins are not assigned to the submitted username.

Passwords, query strings, raw paths for unmatched routes, request bodies, cookies, and arbitrary headers are not stored. Forwarding headers are ignored; source IP comes from the direct connection. Trusted proxy handling must be explicitly configured when adding a deployment proxy.

Administrator views and API requests are logged but marked ineligible for the request-rate detector. Counts describe completed requests before the current dashboard request finishes. Refresh to see the latest completed request. `/health` checks process responsiveness only, not database readiness.

SQLite access follows the [Flask request-scoped connection pattern](https://flask.palletsprojects.com/en/stable/tutorial/database/). Forms use global [Flask-WTF CSRF protection](https://flask-wtf.readthedocs.io/en/1.2.x/csrf/).

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `CLOUDSHIELD_SECRET_KEY` | Required | Random signing secret of at least 32 characters |
| `CLOUDSHIELD_ENV` | `development` | Set `production` for secure-cookie enforcement |
| `CLOUDSHIELD_COOKIE_SECURE` | False locally, true in production | Send session cookies only over HTTPS |
| `CLOUDSHIELD_DATABASE` | `instance/cloudshield.sqlite3` | Optional absolute database file path |
| `CLOUDSHIELD_RULES_FILE` | `app/detection/rules.json` | Optional absolute rule-configuration file path |
| `CLOUDSHIELD_RISK_POLICY_FILE` | `app/risk/policy.json` | Optional absolute risk/response policy file path |

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
  detection/        Configurable rules, source contexts, findings and evidence
  risk/             Score ledger, incidents, actions, worker, recovery and views
  routes.py         Workspace, administrator views and APIs
  templates/        HTML pages
  static/           Stylesheet
migrations/         Versioned SQL schema changes
tests/              Foundation integration tests
scripts/            Bounded local demo traffic generator
```

## Administrator dashboard

Sign in as an administrator. The navigation bar offers:

| Page | Route | Purpose |
| --- | --- | --- |
| Overview | `/admin/overview` | Live event trend, risk history, threat distribution, recent alerts and active blocks; auto-refreshes every 5 seconds with Chart.js charts |
| Investigate | `/admin/investigate` | Tabbed, paginated search across entities, incidents, findings, events and alerts with state filters |
| Risk & incidents | `/admin/risk` | Current entity scores, open incidents, and alert acknowledgement forms |
| Entity detail | `/admin/entities/<id>` | Complete score audit trail (requested/applied deltas, reasons, evidence links) and block history |
| Incident detail | `/admin/incidents/<id>` | Chronological timeline of events, score changes, alerts and block actions |
| Settings | `/admin/settings` | Read-only view of the active detection rules and risk policy with their version fingerprints |

The overview page embeds `dashboard-data` as JSON and polls `/api/dashboard` every 5 seconds. Pause the live refresh with the button in the top right. Selecting a 1-hour, 24-hour or 7-day window applies to both the initial render and all subsequent polls.

## EC2 deployment

The `deploy/` directory contains files ready for a single Amazon EC2 instance running a Debian/Ubuntu-based Linux distribution.

### Prepare the instance

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y python3-venv nginx

# Create a dedicated service account
sudo useradd --system --create-home --home-dir /opt/cloudshield cloudshield

# Copy project files
sudo git clone <your-repo-url> /opt/cloudshield
cd /opt/cloudshield
sudo -u cloudshield python3 -m venv .venv
sudo -u cloudshield .venv/bin/pip install -r requirements.txt

# Prepare the database directory
sudo mkdir -p /var/lib/cloudshield
sudo chown cloudshield:cloudshield /var/lib/cloudshield
sudo chmod 0700 /var/lib/cloudshield
```

### Configure the environment

```bash
sudo cp deploy/production.env.example /etc/cloudshield.env
sudo chmod 0600 /etc/cloudshield.env
sudo nano /etc/cloudshield.env  # Set CLOUDSHIELD_SECRET_KEY to a random 64-character value
```

### Apply the schema and seed the first administrator

```bash
sudo -u cloudshield CLOUDSHIELD_ENV=production \
  CLOUDSHIELD_DATABASE=/var/lib/cloudshield/cloudshield.sqlite3 \
  CLOUDSHIELD_SECRET_KEY=<same-key> \
  .venv/bin/python -m flask --app app init-db
sudo -u cloudshield CLOUDSHIELD_ENV=production \
  CLOUDSHIELD_DATABASE=/var/lib/cloudshield/cloudshield.sqlite3 \
  CLOUDSHIELD_SECRET_KEY=<same-key> \
  .venv/bin/python -m flask --app app create-user --username admin --role admin
```

### Install and enable services

```bash
# Web server and worker
sudo cp deploy/cloudshield-web.service /etc/systemd/system/
sudo cp deploy/cloudshield-worker.service /etc/systemd/system/
sudo cp deploy/cloudshield-migrate.service /etc/systemd/system/
sudo cp deploy/cloudshield-backup.service /etc/systemd/system/
sudo cp deploy/cloudshield-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cloudshield-web cloudshield-worker cloudshield-backup.timer

# nginx reverse proxy
sudo cp deploy/nginx.conf /etc/nginx/sites-available/cloudshield
# Edit /etc/nginx/sites-available/cloudshield: replace cloudshield.example.com with your domain
sudo ln -s /etc/nginx/sites-available/cloudshield /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Install a TLS certificate (e.g. with Certbot) before enabling the nginx configuration. The nginx config rewrites HTTP to HTTPS and sets `Strict-Transport-Security`.

### Verify the deployment

```bash
curl -s http://127.0.0.1:8000/health   # Should return {"status":"ok"}
curl -s http://127.0.0.1:8000/ready    # Should return {"status":"ready"} after migration
sudo systemctl status cloudshield-web cloudshield-worker
sudo journalctl -u cloudshield-web -n 50
```

Check that `/health` returns `ok` and `/ready` returns `ready`. The `/ready` endpoint verifies both database connectivity and that all migrations have been applied; it is only accessible from localhost via the nginx configuration.

### Backup and restore

The `cloudshield-backup.timer` runs a daily SQLite backup using `scripts/backup.py`. Backup files land in `/var/lib/cloudshield/backups/`. To restore:

```bash
sudo systemctl stop cloudshield-web cloudshield-worker
sudo -u cloudshield cp /var/lib/cloudshield/backups/<backup-file>.sqlite3 /var/lib/cloudshield/cloudshield.sqlite3
sudo systemctl start cloudshield-web cloudshield-worker
```

### Security checklist

- `SECRET_KEY` is at least 64 random characters, stored in `/etc/cloudshield.env` with mode `0600`.
- HTTPS is enforced; `CLOUDSHIELD_COOKIE_SECURE=true` and `CLOUDSHIELD_ENV=production` are set.
- The EC2 security group allows only ports 80 and 443 from the internet and 22 (SSH) from a trusted IP.
- The `cloudshield` user has no login shell and no access outside `/opt/cloudshield` and `/var/lib/cloudshield`.
- The nginx configuration strips all forwarding headers and passes only `X-Forwarded-For` (the real client IP) and `X-Forwarded-Proto`.
- `CLOUDSHIELD_TRUST_PROXY=true` in production tells Waitress to trust exactly one proxy hop from localhost.
