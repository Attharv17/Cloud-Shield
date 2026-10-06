"""Consistent SQLite backups, including committed WAL data."""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import click
from flask import current_app
from flask.cli import with_appcontext


def backup_database(source, directory):
    source = Path(source).resolve(strict=True)
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    filename = "cloudshield-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8] + ".sqlite3"
    destination = directory / filename
    with destination.open("xb"):
        pass
    try:
        with sqlite3.connect(source.as_uri() + "?mode=ro", uri=True) as origin:
            with sqlite3.connect(destination) as target:
                origin.backup(target)
                if target.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise RuntimeError("Backup integrity check failed.")
            target.close()
        origin.close()
    except Exception:
        # Only the new file created by this invocation is removed on failure.
        destination.unlink(missing_ok=True)
        raise
    return destination


@click.command("backup-db")
@click.option("--directory", required=True, type=click.Path(file_okay=False, path_type=Path))
@with_appcontext
def backup_command(directory):
    """Write a new, integrity-checked SQLite snapshot without overwriting older backups."""
    click.echo(f"Backup verified: {backup_database(current_app.config['DATABASE'], directory)}")
