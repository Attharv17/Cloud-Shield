from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, g, jsonify, render_template, request
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.exceptions import HTTPException

from .config import configuration

csrf = CSRFProtect()


def create_app(test_config=None):
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(configuration(app.instance_path))
    if test_config:
        app.config.update(test_config)
    secret = app.config.get("SECRET_KEY")
    if not secret or len(secret) < 32 or secret.startswith("replace-with-"):
        raise RuntimeError("Set CLOUDSHIELD_SECRET_KEY to a random secret of at least 32 characters.")
    if app.config["ENVIRONMENT"] == "production" and not app.config["SESSION_COOKIE_SECURE"]:
        raise RuntimeError("Production requires secure session cookies and HTTPS.")
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    from . import auth, collection, dashboard, db, detection, risk, routes

    db.init_app(app)
    collection.init_app(app)
    auth.init_app(app)
    detection.init_app(app)
    risk.init_app(app)
    csrf.init_app(app)
    app.register_blueprint(routes.bp)
    app.register_blueprint(routes.api)
    app.register_blueprint(dashboard.bp)
    from scripts.demo_traffic import demo_traffic_command
    app.cli.add_command(demo_traffic_command)
    from scripts.backup import backup_command
    app.cli.add_command(backup_command)

    @app.errorhandler(CSRFError)
    def csrf_error(_error):
        g.event_type = "csrf_rejected"
        message = "Your form expired or could not be verified. Reload the page and try again."
        if request.path.startswith("/api/"):
            return jsonify(error=message), 400
        return render_template("error.html", code=400, message=message), 400

    @app.errorhandler(HTTPException)
    def http_error(error):
        if request.path.startswith("/api/"):
            return jsonify(error=error.name), error.code
        return render_template("error.html", code=error.code, message=error.description), error.code

    return app
