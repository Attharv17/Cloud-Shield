"""Request-scoped SQLite connections and additive, versioned migrations."""

import sqlite3
from pathlib import Path

import click
from flask import current_app, g
from flask.cli import with_appcontext


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def migrate():
    database_path = Path(current_app.config["DATABASE"])
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = get_db()
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    connection.commit()
    migration_path = Path(current_app.root_path).parent / "migrations"
    for path in sorted(migration_path.glob("[0-9]*.sql")):
        version = path.stem
        if connection.execute(
            "SELECT 1 FROM schema_migrations WHERE version = ?", (version,)
        ).fetchone():
            continue
        # Migration filenames and SQL are trusted repository code, never request data.
        escaped_version = version.replace("'", "''")
        try:
            connection.executescript(
                "BEGIN IMMEDIATE;\n" + path.read_text(encoding="utf-8")
                + "\nINSERT INTO schema_migrations VALUES ('"
                + escaped_version + "', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));\nCOMMIT;"
            )
        except sqlite3.Error:
            connection.rollback()
            raise


@click.command("init-db")
@with_appcontext
def init_db_command():
    """Apply pending migrations without deleting existing data."""
    migrate()
    click.echo("Database is ready; all migrations applied.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
