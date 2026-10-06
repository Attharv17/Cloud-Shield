"""A signed browser marker is context, never an authentication credential."""

import hashlib
import hmac
import secrets

from flask import current_app, g, request
from itsdangerous import BadData, URLSafeTimedSerializer

COOKIE_NAME = "cloudshield_device"
MAX_AGE = 365 * 24 * 60 * 60


def load_device_context():
    signer = URLSafeTimedSerializer(current_app.secret_key, salt="cloudshield-device-v1")
    supplied = request.cookies.get(COOKIE_NAME, "")
    marker = None
    if supplied and len(supplied) <= 256:
        try:
            candidate = signer.loads(supplied, max_age=MAX_AGE)
            if isinstance(candidate, str) and len(candidate) == 43:
                marker = candidate
        except BadData:
            pass
    g.device_cookie = None
    if marker is None:
        marker = secrets.token_urlsafe(32)
        g.device_cookie = signer.dumps(marker)
    g.device_fingerprint = hmac.new(
        current_app.secret_key.encode(), ("device:" + marker).encode(), hashlib.sha256
    ).hexdigest()


def set_device_cookie(response):
    if getattr(g, "device_cookie", None) and request.endpoint not in {"static", "main.health", "main.ready"}:
        response.set_cookie(
            COOKIE_NAME, g.device_cookie, max_age=MAX_AGE,
            secure=current_app.config["SESSION_COOKIE_SECURE"], httponly=True, samesite="Lax",
        )
    return response
