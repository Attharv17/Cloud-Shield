"""One-time script to create default admin and demo users for development."""
import sqlite3
import sys
import os

# Load .env manually so CLOUDSHIELD_SECRET_KEY is available
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

from app import create_app
from app.models import create_user
from app.db import get_db

USERS = [
    {"username": "admin", "password": "AdminPass123!", "role": "admin"},
    {"username": "demo",  "password": "DemoPass1234!",  "role": "user"},
]

app = create_app()
with app.app_context():
    for u in USERS:
        try:
            create_user(u["username"], u["password"], u["role"])
            print(f"[OK] Created {u['role']} account: {u['username']}")
        except sqlite3.IntegrityError:
            print(f"[SKIP] User '{u['username']}' already exists.")
        except ValueError as e:
            print(f"[ERROR] {e}", file=sys.stderr)
