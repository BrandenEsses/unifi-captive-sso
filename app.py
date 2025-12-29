import configparser
import os
from pathlib import Path

from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, render_template, session, url_for


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def load_config(app: Flask) -> None:
    config_path = os.environ.get("UNIFI_CONFIG_PATH")
    if config_path:
        config_file = Path(config_path)
        if not config_file.is_absolute():
            config_file = (Path(__file__).resolve().parent / config_file).resolve()
    else:
        config_file = Path(__file__).resolve().parent / "config.ini"
    parser = configparser.ConfigParser()
    if config_file.is_file():
        parser.read(config_file)

    unifi = parser["unifi"] if "unifi" in parser else None
    oidc = parser["oidc"] if "oidc" in parser else None

    def env_or_section(env_key: str, section, key: str, fallback=None):
        if env_key in os.environ:
            return os.environ[env_key]
        if section is not None and section.get(key) is not None:
            return section.get(key)
        return fallback

    base_url = env_or_section("UNIFI_BASE_URL", unifi, "base_url", "")
    app.config["UNIFI_BASE_URL"] = base_url.rstrip("/")
    app.config["UNIFI_SITE"] = env_or_section("UNIFI_SITE", unifi, "site", "default")
    app.config["UNIFI_USERNAME"] = env_or_section("UNIFI_USERNAME", unifi, "username")
    app.config["UNIFI_PASSWORD"] = env_or_section("UNIFI_PASSWORD", unifi, "password")

    verify_ssl_env = os.environ.get("UNIFI_VERIFY_SSL")
    if verify_ssl_env is not None:
        app.config["UNIFI_VERIFY_SSL"] = _parse_bool(verify_ssl_env)
    elif unifi and "verify_ssl" in unifi:
        app.config["UNIFI_VERIFY_SSL"] = unifi.getboolean("verify_ssl")
    else:
        app.config["UNIFI_VERIFY_SSL"] = True

    app.config["OIDC_CLIENT_ID"] = env_or_section(
        "OIDC_CLIENT_ID", oidc, "client_id"
    )
    app.config["OIDC_CLIENT_SECRET"] = env_or_section(
        "OIDC_CLIENT_SECRET", oidc, "client_secret"
    )
    app.config["OIDC_METADATA_URL"] = env_or_section(
        "OIDC_METADATA_URL", oidc, "metadata_url"
    )
    app.config["OIDC_SCOPE"] = env_or_section(
        "OIDC_SCOPE", oidc, "scope", "openid email profile"
    )


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev")
    load_config(app)

    oauth = OAuth(app)

    def sso_configured() -> bool:
        return all(
            app.config.get(key)
            for key in ("OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_METADATA_URL")
        )

    if sso_configured():
        oauth.register(
            name="oidc",
            client_id=app.config["OIDC_CLIENT_ID"],
            client_secret=app.config["OIDC_CLIENT_SECRET"],
            server_metadata_url=app.config["OIDC_METADATA_URL"],
            client_kwargs={"scope": app.config["OIDC_SCOPE"]},
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
                error="SSO is not configured. Set [oidc] client_id, "
                "client_secret, and metadata_url in config.ini.",
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
