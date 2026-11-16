# CloudShield solution architecture

![CloudShield solution architecture](architecture.png)

The diagram reflects the implementation in this repository. The single EC2 host is the deployment target supported by `deploy/`; it does not imply that a live deployment has been verified. For local development, Flask's development server replaces Nginx and Waitress.

Download the [vector diagram](architecture.svg) or [PNG](architecture.png). The editable diagram below describes the same components.

```mermaid
flowchart TB
    users[Users / demo browser]
    admin[Administrator browser<br/>HTML + JavaScript + Chart.js]

    subgraph host[Single EC2 host — deployment target]
        proxy[Nginx<br/>HTTPS termination / trusted forwarding headers]
        wsgi[Waitress<br/>127.0.0.1:8000]
        subgraph flask[Flask application — one synchronous backend]
            gate[Session authentication + block enforcement<br/>Catch-up maintenance before enforcement]
            routes[Application / authentication routes<br/>Admin-only dashboard + JSON APIs / CSRF]
            subgraph transaction[Completed-request telemetry — one SQLite write transaction]
                collect[Collection + normalization<br/>Allowlisted metadata / request IDs]
                detect[Detection engine<br/>Failed logins / request rate / restricted access / new context]
                risk[Risk engine<br/>Separate IP + verified-user scores / bounds 0–100<br/>Weighted findings + guarded normal reductions]
                response[Incident + response logic<br/>Evidence timelines / alerts / temporary blocks]
                collect --> detect --> risk --> response
            end
            gate --> routes
            gate -->|Blocked request: HTTP 429| collect
            routes -->|after_request hook| collect
        end
        db[(SQLite persistent database<br/>Users / events / findings / source history<br/>Scores + ledger / incidents / alerts / actions / config versions)]
        worker[Separate risk-worker process<br/>10-second loop / decay / close quiet incidents<br/>Expire or renew blocks]
        backup[Daily systemd backup timer<br/>Verified SQLite snapshots]
        recovery[Administrator recovery CLI<br/>Authenticated score reset + block revocation / audit]
        policy[Versioned JSON configuration<br/>detection/rules.json + risk/policy.json]
        proxy --> wsgi --> gate
        transaction <-->|read + atomic write| db
        gate <-->|current blocks + maintenance| db
        routes <-->|authorized queries + alert acknowledgement| db
        worker <-->|coordinated transactions| db
        db --> backup
        recovery --> db
        policy -.-> detect
        policy -.-> risk
        policy -.-> worker
    end
    users <-->|HTTPS| proxy
    admin <-->|HTTPS / dashboard polls every 5 seconds| proxy
```

- Events, findings, source history, risk changes, incidents and actions commit together. These modules run in-process; the telemetry pipeline does not use a message queue.
- Effective risk is the higher of the IP and authenticated-user scores. Anonymous failed logins affect only the IP. Defaults are low 0–24, medium 25–49, high 50–74 and critical 75–100.
- High and critical escalation creates dashboard alerts. Critical risk creates a five-minute application block enforced on subsequent requests. Blocked traffic is logged without adding findings or risk.
- The separate worker applies −10 per complete five-minute quiet interval, closes incidents after ten minutes without a finding, and handles block expiry or renewal. Request-time catch-up uses the same maintenance logic.
- CAPTCHA is a recommendation. Email, WAF/IAM remediation, ML detection and multi-cloud telemetry are future integrations.

Implementation references: `app/server.py`, `app/__init__.py`, `app/collection/__init__.py`, `app/models.py`, `app/detection/`, `app/risk/`, `app/dashboard.py`, `app/static/dashboard.js`, `migrations/` and `deploy/`.
