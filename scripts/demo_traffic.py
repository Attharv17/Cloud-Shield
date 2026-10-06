"""Bounded demo requests through Flask itself; no outbound network traffic."""

import re
import secrets

import click
from flask import current_app
from flask.cli import with_appcontext
from werkzeug.security import check_password_hash

from app.db import get_db
from app.models import find_user


def _request(client, method, path, **kwargs):
    # CLI commands keep an app context alive. Give each simulated request its own
    # context so g (including Flask-WTF's cached CSRF token) cannot leak across requests.
    with current_app._get_current_object().app_context():
        return client.open(path, method=method, **kwargs)


def _login(client, username, password):
    page = _request(client, "GET", "/auth/login")
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True))
    if not match:
        raise click.ClickException("Demo login form did not provide a CSRF token.")
    return _request(client, "POST", "/auth/login", data={
        "username": username, "password": password, "csrf_token": match.group(1),
    })


def run_demo(username, password):
    app = current_app._get_current_object()
    if app.config["ENVIRONMENT"] != "development":
        raise click.ClickException("Demo traffic is available only in the development environment.")
    user = find_user(username)
    if user is None or not check_password_hash(user["password_hash"], password):
        raise click.ClickException("Invalid demo account credentials.")
    if user["role"] != "user":
        raise click.ClickException("Use an ordinary user account so restricted-access detection can be demonstrated.")
    rules = app.extensions["detection"]["rules"]
    failures = rules["failed_login_burst"]["threshold"]
    requests = rules["high_request_frequency"]["threshold"] + 1
    if failures > 25 or requests > 201:
        raise click.ClickException("Demo limits are 25 failed logins and 201 page requests; lower your rule thresholds.")
    last_id = get_db().execute("SELECT COALESCE(MAX(id), 0) FROM findings").fetchone()[0]
    client = app.test_client()
    client.environ_base["REMOTE_ADDR"] = "192.0.2.10"
    if _login(client, username, password).status_code != 302:
        raise click.ClickException("Baseline login failed.")
    wrong_password = secrets.token_urlsafe(32)
    for _ in range(failures):
        if _login(client, username, wrong_password).status_code != 401:
            raise click.ClickException("Expected a failed-login response.")
    if _login(client, username, password).status_code != 302:
        raise click.ClickException("Demo login failed.")
    if _request(client, "GET", "/admin").status_code != 403:
        raise click.ClickException("Expected the administrator route to reject the demo account.")
    for _ in range(requests):
        if _request(client, "GET", "/").status_code != 200:
            raise click.ClickException("Demo page request failed.")
    unfamiliar_browser = app.test_client()
    unfamiliar_browser.environ_base["REMOTE_ADDR"] = "192.0.2.10"
    if _login(unfamiliar_browser, username, password).status_code != 302:
        raise click.ClickException("New-browser login failed.")
    return [dict(row) for row in get_db().execute(
        "SELECT id, rule_id, weight, reason FROM findings WHERE id > ? ORDER BY id", (last_id,)
    )]


@click.command("demo-traffic")
@click.option("--username", required=True, help="Existing ordinary local account.")
@click.password_option(confirmation_prompt=False)
@with_appcontext
def demo_traffic_command(username, password):
    """Generate bounded local events in the configured development database."""
    findings = run_demo(username, password)
    click.echo("Local scenarios completed using simulated source IP 192.0.2.10; no network requests sent.")
    for finding in findings:
        click.echo(f"#{finding['id']} {finding['rule_id']} (+{finding['weight']}): {finding['reason']}")
    click.echo(f"{len(findings)} new findings. Existing cooldowns may suppress repeat scenarios.")
