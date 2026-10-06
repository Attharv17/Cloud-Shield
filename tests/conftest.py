import re

import pytest

from app import create_app
from app.db import migrate
from app.models import create_user

PASSWORD = "test-password-only-123"


@pytest.fixture
def app(tmp_path):
    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-not-for-deployment-1234567890",
        "DATABASE": str(tmp_path / "test.sqlite3"),
        "SESSION_COOKIE_SECURE": False,
        "ENVIRONMENT": "testing",
        "DETECTION_RULES_FILE": None,
        "RISK_POLICY_FILE": None,
    })
    with application.app_context():
        migrate()
        create_user("analyst", PASSWORD, "user")
        create_user("administrator", PASSWORD, "admin")
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def token(response):
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True))
    assert match, "Page must contain a CSRF-protected form"
    return match.group(1)


def login(client, username="analyst", password=PASSWORD):
    csrf_token = token(client.get("/auth/login"))
    return client.post("/auth/login", data={
        "username": username, "password": password, "csrf_token": csrf_token,
    })
