import configparser
import os
from pathlib import Path

from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, render_template, session, url_for


def load_unifi_config(app: Flask) -> None:
    config_path = os.environ.get("UNIFI_CONFIG_PATH", "config.ini")
    config_file = Path(config_path)
    if not config_file.is_file():
        return
    parser = configparser.ConfigParser()
    parser.read(config_file)
    if "unifi" not in parser:
        return
    section = parser["unifi"]
    app.config["UNIFI_BASE_URL"] = section.get("base_url", "").rstrip("/")
    app.config["UNIFI_SITE"] = section.get("site", "default")
    app.config["UNIFI_USERNAME"] = section.get("username")
    app.config["UNIFI_PASSWORD"] = section.get("password")
    app.config["UNIFI_VERIFY_SSL"] = section.getboolean("verify_ssl", fallback=True)


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev")
    load_unifi_config(app)

    oauth = OAuth(app)

    def sso_configured() -> bool:
        return all(
            os.environ.get(key)
            for key in ("OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_METADATA_URL")
        )

    if sso_configured():
        oauth.register(
            name="oidc",
            client_id=os.environ["OIDC_CLIENT_ID"],
            client_secret=os.environ["OIDC_CLIENT_SECRET"],
            server_metadata_url=os.environ["OIDC_METADATA_URL"],
            client_kwargs={"scope": "openid email profile"},
        )

    @app.get("/")
    def index():
        return render_template(
            "index.html", sso_configured=sso_configured(), user=session.get("user")
        )

    @app.get("/login")
    def login():
        if not sso_configured():
            return render_template(
                "index.html",
                sso_configured=False,
                user=session.get("user"),
                error="SSO is not configured. Set OIDC_CLIENT_ID, "
                "OIDC_CLIENT_SECRET, and OIDC_METADATA_URL.",
            ), 500
        redirect_uri = url_for("auth_callback", _external=True)
        return oauth.oidc.authorize_redirect(redirect_uri)

    @app.get("/auth/callback")
    def auth_callback():
        if not sso_configured():
            return redirect(url_for("index"))
        token = oauth.oidc.authorize_access_token()
        userinfo = token.get("userinfo") or oauth.oidc.parse_id_token(token)
        session["user"] = {
            "sub": userinfo.get("sub"),
            "email": userinfo.get("email"),
            "name": userinfo.get("name")
            or userinfo.get("preferred_username")
            or userinfo.get("email"),
        }
        return redirect(url_for("success"))

    @app.get("/success")
    def success():
        return render_template("success.html", user=session.get("user"))

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    return app


app = create_app()
