"""Allowlisted event capture. Never persist arbitrary request data."""

from uuid import uuid4

from flask import g, request

from ..models import save_event, utc_now


def begin_request():
    g.request_id = str(uuid4())
    g.event_time = utc_now()
    g.event_type = "application_request"


def finish_request(response):
    response.headers["X-Request-ID"] = g.request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    if request.endpoint == "static" or request.endpoint == "main.health":
        return response
    response.headers["Cache-Control"] = "no-store"
    user = getattr(g, "user", None)
    # Store the route template, not raw paths, query strings, headers or bodies.
    # Forwarded headers are deliberately untrusted until a real proxy is configured.
    save_event({
        "request_id": g.request_id,
        "timestamp": g.event_time,
        "event_type": g.event_type,
        "source_ip": request.remote_addr or "unknown",
        "user_id": user["id"] if user is not None else None,
        "route": request.url_rule.rule if request.url_rule else "(unmatched)",
        "method": request.method,
        "status": response.status_code,
        "metadata": {
            "authenticated": user is not None,
            "rate_eligible": request.endpoint not in {"main.admin", "api.events", "api.overview"},
        },
    })
    return response


def init_app(app):
    app.before_request(begin_request)
    app.after_request(finish_request)
