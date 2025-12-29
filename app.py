import configparser
import hashlib
import os
import re
from datetime import date
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from authlib.integrations.flask_client import OAuth
from flask import (
    Flask,
    flash,
    get_flashed_messages,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
import requests


DEFAULT_AUTHORIZE_MINUTES = 480
DEFAULT_GUEST_MINUTES = 1440
DEFAULT_SSO_MINUTES = 43200
MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
MAC_PATTERN = re.compile(
    r"(?:(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12})"
)


@lru_cache(maxsize=1)
def load_wordlist():
    wordlist_path = Path(__file__).resolve().parent / "wordlist.txt"
    try:
        contents = wordlist_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    words = []
    for line in contents.splitlines():
        word = line.strip().lower()
        if not word or word.startswith("#"):
            continue
        words.append(word)
    return words


def daily_guest_password() -> str:
    words = load_wordlist()
    if len(words) < 2:
        return ""
    digest = hashlib.sha256(date.today().isoformat().encode("utf-8")).digest()
    idx_a = int.from_bytes(digest[:4], "big") % len(words)
    idx_b = int.from_bytes(digest[4:8], "big") % len(words)
    if idx_b == idx_a:
        idx_b = (idx_b + 1) % len(words)
    return f"{words[idx_a]}{words[idx_b]}"


def normalize_mac(value: str):
    if not value:
        return None
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(cleaned) != 12:
        return None
    cleaned = cleaned.lower()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def find_mac_in_text(value: str):
    if not value:
        return None
    match = MAC_PATTERN.search(value)
    if not match:
        return None
    return normalize_mac(match.group(0))


def extract_client_mac(args):
    for key in (
        "client_mac",
        "clientmac",
        "client-mac",
        "mac",
        "id",
        "client_id",
        "client-id",
        "sta",
    ):
        value = normalize_mac(args.get(key, "").strip())
        if value and MAC_RE.match(value):
            return value
    for value in args.values():
        candidate = normalize_mac(str(value))
        if candidate and MAC_RE.match(candidate):
            return candidate
        candidate = find_mac_in_text(str(value))
        if candidate and MAC_RE.match(candidate):
            return candidate
    return None


def extract_client_mac_from_request(req):
    for source in (req.args, req.form):
        mac = extract_client_mac(source)
        if mac:
            return mac
    for header in ("X-Client-MAC", "X-Auth-Client-MAC", "X-Device-MAC"):
        mac = normalize_mac(req.headers.get(header, ""))
        if mac and MAC_RE.match(mac):
            return mac
    if req.referrer:
        mac = find_mac_in_text(req.referrer)
        if mac and MAC_RE.match(mac):
            return mac
    return None


def unifi_configured(app: Flask) -> bool:
    return all(
        app.config.get(key)
        for key in ("UNIFI_BASE_URL", "UNIFI_USERNAME", "UNIFI_PASSWORD")
    )


def unifi_login_session(app: Flask):
    if not unifi_configured(app):
        return None, "UniFi config is missing base_url, username, or password."

    base_url = app.config["UNIFI_BASE_URL"].rstrip("/")
    verify_ssl = app.config.get("UNIFI_VERIFY_SSL", True)

    session_client = requests.Session()
    session_client.verify = verify_ssl

    try:
        login_response = session_client.post(
            f"{base_url}/api/auth/login",
            json={
                "username": app.config["UNIFI_USERNAME"],
                "password": app.config["UNIFI_PASSWORD"],
            },
            timeout=10,
        )
    except requests.RequestException as exc:
        return None, f"UniFi request failed: {exc}"

    if not login_response.ok:
        return None, f"UniFi login failed ({login_response.status_code})."

    csrf_token = login_response.headers.get("X-CSRF-Token")
    if csrf_token:
        session_client.headers.update({"X-CSRF-Token": csrf_token})

    return session_client, None


def unifi_error_message(response, fallback: str) -> str:
    try:
        payload = response.json()
    except ValueError:
        return fallback
    if isinstance(payload, dict):
        meta = payload.get("meta")
        if isinstance(meta, dict):
            msg = meta.get("msg") or meta.get("message")
            if msg:
                return f"{fallback} {msg}"
        message = payload.get("message")
        if message:
            return f"{fallback} {message}"
    return fallback


def parse_unifi_status_payload(payload):
    data = payload.get("data") if isinstance(payload, dict) else None
    if not data:
        return "not_found", "Device not visible yet."

    entry = data[0] or {}
    if entry.get("authorized") is True:
        return "authorized", "Device is authorized."
    if entry.get("blocked") is True or entry.get("is_blocked") is True:
        return "blocked", "Device is blocked."

    state = str(entry.get("state", "")).lower()
    if state in ("authorized", "auth"):
        return "authorized", "Device is authorized."

    return "pending", "Waiting for authorization."


def unifi_client_status(app: Flask, mac: str):
    session_client, error = unifi_login_session(app)
    if error:
        return "error", error

    base_url = app.config["UNIFI_BASE_URL"].rstrip("/")
    site = app.config.get("UNIFI_SITE", "default")

    mac_path = quote(mac, safe="")
    endpoints = [
        f"{base_url}/proxy/network/api/s/{site}/stat/sta/{mac_path}",
        f"{base_url}/proxy/network/api/s/{site}/stat/sta?mac={mac}",
    ]

    last_error = None
    for url in endpoints:
        try:
            status_response = session_client.get(url, timeout=10)
        except requests.RequestException as exc:
            return "error", f"UniFi request failed: {exc}"

        if status_response.ok:
            try:
                payload = status_response.json()
            except ValueError:
                return "error", "UniFi returned non-JSON."
            return parse_unifi_status_payload(payload)

        last_error = unifi_error_message(
            status_response, f"UniFi status failed ({status_response.status_code})."
        )
        if status_response.status_code not in (400, 404):
            return "error", last_error

    return "error", last_error or "UniFi status failed."


def unifi_authorize_mac(app: Flask, mac: str, minutes=None):
    session_client, error = unifi_login_session(app)
    if error:
        return False, error

    base_url = app.config["UNIFI_BASE_URL"].rstrip("/")
    site = app.config.get("UNIFI_SITE", "default")
    if minutes is None:
        minutes = app.config.get("UNIFI_AUTHORIZE_MINUTES", DEFAULT_AUTHORIZE_MINUTES)

    try:
        authorize_response = session_client.post(
            f"{base_url}/proxy/network/api/s/{site}/cmd/stamgr",
            json={"cmd": "authorize-guest", "mac": mac, "minutes": minutes},
            timeout=10,
        )
    except requests.RequestException as exc:
        return False, f"UniFi request failed: {exc}"

    if not authorize_response.ok:
        return False, f"UniFi authorize failed ({authorize_response.status_code})."
    try:
        payload = authorize_response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        rc = payload.get("meta", {}).get("rc")
        if rc and rc != "ok":
            return False, payload.get("meta", {}).get("msg", "UniFi error.")
    return True, f"Authorized {mac} for {minutes} minutes."


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def _parse_minutes(value, fallback: int) -> int:
    if value is None:
        return fallback
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


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

    authorize_minutes = env_or_section(
        "UNIFI_AUTHORIZE_MINUTES", unifi, "authorize_minutes"
    )
    parsed_authorize_minutes = _parse_minutes(
        authorize_minutes, DEFAULT_AUTHORIZE_MINUTES
    )
    app.config["UNIFI_AUTHORIZE_MINUTES"] = parsed_authorize_minutes

    guest_minutes = env_or_section("UNIFI_GUEST_MINUTES", unifi, "guest_minutes")
    if guest_minutes is None:
        guest_fallback = (
            parsed_authorize_minutes
            if authorize_minutes is not None
            else DEFAULT_GUEST_MINUTES
        )
        app.config["UNIFI_GUEST_MINUTES"] = guest_fallback
    else:
        app.config["UNIFI_GUEST_MINUTES"] = _parse_minutes(
            guest_minutes, DEFAULT_GUEST_MINUTES
        )

    sso_minutes = env_or_section("UNIFI_SSO_MINUTES", unifi, "sso_minutes")
    if sso_minutes is None:
        sso_fallback = (
            parsed_authorize_minutes
            if authorize_minutes is not None
            else DEFAULT_SSO_MINUTES
        )
        app.config["UNIFI_SSO_MINUTES"] = sso_fallback
    else:
        app.config["UNIFI_SSO_MINUTES"] = _parse_minutes(
            sso_minutes, DEFAULT_SSO_MINUTES
        )

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
        client_mac = extract_client_mac_from_request(request) or session.get(
            "client_mac"
        )
        if client_mac:
            session["client_mac"] = client_mac
        user = session.get("user")
        return render_template(
            "index.html",
            sso_configured=sso_configured(),
            unifi_configured=unifi_configured(app),
            user=user,
            guest_password=daily_guest_password() if user else "",
            guest_authenticated=session.get("guest_authenticated", False),
            client_mac=client_mac,
            messages=get_flashed_messages(with_categories=True),
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
        client_mac = session.get("client_mac") or extract_client_mac_from_request(
            request
        )
        if client_mac:
            session["client_mac"] = client_mac
        if client_mac:
            ok, message = unifi_authorize_mac(
                app,
                client_mac,
                minutes=app.config.get("UNIFI_SSO_MINUTES", DEFAULT_SSO_MINUTES),
            )
            flash(message, "success" if ok else "error")
        return redirect(url_for("index"))

    @app.get("/success")
    def success():
        return render_template("success.html", user=session.get("user"))

    @app.post("/devices/authorize")
    def authorize_device():
        if not session.get("user"):
            flash("Sign in with SSO to add devices.", "error")
            return redirect(url_for("index"))
        mac = normalize_mac(request.form.get("mac", "").strip())
        if not mac or not MAC_RE.match(mac):
            flash("Enter a valid MAC address (aa:bb:cc:dd:ee:ff).", "error")
            return redirect(url_for("index"))
        session["client_mac"] = mac
        ok, message = unifi_authorize_mac(
            app,
            mac,
            minutes=app.config.get("UNIFI_SSO_MINUTES", DEFAULT_SSO_MINUTES),
        )
        flash(message, "success" if ok else "error")
        return redirect(url_for("index"))

    @app.post("/guest/authorize")
    def authorize_guest():
        entered = request.form.get("guest_password", "").strip().lower()
        expected = daily_guest_password()
        if not expected:
            flash("Guest password is not configured.", "error")
            return redirect(url_for("index"))
        if entered != expected:
            flash("Guest password is incorrect.", "error")
            return redirect(url_for("index"))

        mac = extract_client_mac_from_request(request) or normalize_mac(
            session.get("client_mac", "")
        )
        if not mac or not MAC_RE.match(mac):
            flash("Missing or invalid client MAC address.", "error")
            return redirect(url_for("index"))

        session["guest_authenticated"] = True
        session["client_mac"] = mac
        ok, message = unifi_authorize_mac(
            app,
            mac,
            minutes=app.config.get("UNIFI_GUEST_MINUTES", DEFAULT_GUEST_MINUTES),
        )
        flash(message, "success" if ok else "error")
        return redirect(url_for("index"))

    @app.get("/status")
    def status():
        mac = session.get("client_mac") or extract_client_mac_from_request(request)
        if not mac or not MAC_RE.match(mac):
            return jsonify({"status": "error", "message": "Missing MAC address."}), 400
        status_value, message = unifi_client_status(app, mac)
        return jsonify({"status": status_value, "message": message, "mac": mac})

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    return app


app = create_app()
