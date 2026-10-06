"""Loopback-only WSGI entry point for the supplied single-proxy deployment."""
import os

from waitress import serve

from . import create_app


def main():
    app = create_app()
    trust_proxy = os.getenv("CLOUDSHIELD_TRUST_PROXY", "false").lower() == "true"
    options = {"host": "127.0.0.1", "port": int(os.getenv("CLOUDSHIELD_PORT", "8000")),
               "threads": 4, "max_request_body_size": app.config["MAX_CONTENT_LENGTH"]}
    if trust_proxy:
        options.update(trusted_proxy="127.0.0.1", trusted_proxy_count=1,
                       trusted_proxy_headers={"x-forwarded-for", "x-forwarded-proto"})
    serve(app, **options)


if __name__ == "__main__":
    main()
