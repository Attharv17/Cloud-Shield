import time

import click
from flask.cli import with_appcontext
from werkzeug.security import check_password_hash

from ..models import find_user
from . import recover, tick


@click.command("risk-maintain")
@with_appcontext
def maintenance_command():
    """Apply elapsed decay, close quiet incidents, and expire/renew blocks once."""
    click.echo(f"Risk maintenance completed at {tick()}.")


@click.command("risk-worker")
@click.option("--interval", type=click.IntRange(1, 60), default=10, show_default=True)
@with_appcontext
def worker_command(interval):
    """Run maintenance until Ctrl+C; no incoming traffic is required."""
    click.echo(f"Risk worker running every {interval} seconds. Stop with Ctrl+C.")
    try:
        while True:
            tick()
            time.sleep(interval)
    except KeyboardInterrupt:
        click.echo("Risk worker stopped.")


@click.command("recover-entity")
@click.option("--entity-id", type=click.IntRange(1), required=True)
@click.option("--admin-username", required=True)
@click.option("--reason", required=True)
@click.password_option(confirmation_prompt=False)
@with_appcontext
def recover_command(entity_id, admin_username, reason, password):
    """Authenticate locally, reset one entity to zero and revoke its active blocks."""
    actor = find_user(admin_username)
    if actor is None or actor["role"] != "admin" or not check_password_hash(actor["password_hash"], password):
        raise click.ClickException("Invalid administrator credentials.")
    reason = reason.strip()
    if not 5 <= len(reason) <= 500:
        raise click.ClickException("Provide an audit reason containing 5-500 characters.")
    try:
        recover(entity_id, actor["id"], reason)
    except ValueError as error:
        raise click.ClickException(str(error)) from error
    click.echo(f"Entity {entity_id} reset and active blocks revoked. Recovery was audited.")
