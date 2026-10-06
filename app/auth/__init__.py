"""Session authentication and server-side role checks."""

import secrets
import sqlite3
from functools import wraps

import click
from flask import Blueprint, abort, g, redirect, render_template, request, session, url_for
from flask.cli import with_appcontext
from werkzeug.security import check_password_hash, generate_password_hash

from ..models import create_user, find_user, get_user

bp = Blueprint("auth", __name__, url_prefix="/auth")
# Match password hashing work for an unknown username without storing a usable password.
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(32))


def load_user():
    user_id = session.get("user_id")
    g.user = get_user(user_id) if isinstance(user_id, int) else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            g.event_type = "access_denied"
            if request.path.startswith("/api/"):
                abort(401)
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "admin":
            g.event_type = "access_denied"
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        session.clear()
        g.user = None
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = find_user(username) if len(username) <= 64 else None
        valid_password = check_password_hash(
            user["password_hash"] if user else _DUMMY_HASH, password[:256]
        )
        if user is None or not valid_password or not 12 <= len(password) <= 256:
            g.event_type = "login_failed"
            error = "Invalid username or password."
            return render_template("login.html", error=error), 401
        session["user_id"] = user["id"]
        session.permanent = True
        g.user = user
        g.event_type = "login_success"
        return redirect(url_for("main.home"))
    return render_template("login.html", error=error)


@bp.post("/logout")
@login_required
def logout():
    g.event_type = "logout"
    # Retain the authenticated actor in g for this request's audit record only.
    session.clear()
    return redirect(url_for("auth.login"))


@click.command("create-user")
@click.option("--username", prompt=True)
@click.option("--role", type=click.Choice(["user", "admin"]), default="user", show_default=True)
@click.password_option(confirmation_prompt=True)
@with_appcontext
def create_user_command(username, role, password):
    """Create a local account; existing accounts are never overwritten."""
    try:
        create_user(username, password, role)
    except ValueError as error:
        raise click.ClickException(str(error)) from error
    except sqlite3.IntegrityError as error:
        raise click.ClickException("That username already exists.") from error
    click.echo(f"Created {role} account: {username.strip().lower()}")


def init_app(app):
    app.before_request(load_user)
    app.register_blueprint(bp)
    app.cli.add_command(create_user_command)
