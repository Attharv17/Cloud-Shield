"""Environment configuration, evaluated when the application is created."""

import os
from datetime import timedelta
from pathlib import Path


def configuration(instance_path):
    environment = os.getenv("CLOUDSHIELD_ENV", "development")
    return {
        "SECRET_KEY": os.getenv("CLOUDSHIELD_SECRET_KEY"),
        "DATABASE": os.getenv(
            "CLOUDSHIELD_DATABASE", str(Path(instance_path) / "cloudshield.sqlite3")
        ),
        "ENVIRONMENT": environment,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_SECURE": os.getenv(
            "CLOUDSHIELD_COOKIE_SECURE", "true" if environment == "production" else "false"
        ).lower() == "true",
        "PERMANENT_SESSION_LIFETIME": timedelta(hours=1),
        "MAX_CONTENT_LENGTH": 16 * 1024,
        "DETECTION_RULES_FILE": os.getenv("CLOUDSHIELD_RULES_FILE"),
        "RISK_POLICY_FILE": os.getenv("CLOUDSHIELD_RISK_POLICY_FILE"),
    }
