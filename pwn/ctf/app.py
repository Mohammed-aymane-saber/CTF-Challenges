"""ISSAWA CITY web interface (read-only).

Reads the user data files produced by ``vuln`` and displays the five
profile fields on a dashboard. Authentication mirrors the binary:
the password is stored alongside the user's JSON in ``DATA_DIR`` as
``<username>.pass``.
"""

import os
import re

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

DATA_DIR = os.environ.get("DATA_DIR", "/app/data")
ALNUM_RE = re.compile(r"^[A-Za-z0-9]+$")
LINE_RE = re.compile(r'^\{"(field\d+)":\s*"(.*)"\}\s*$', re.DOTALL)
FIELD_KEYS = [f"field{i}" for i in range(1, 6)]

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET") or os.urandom(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def _safe_username(username):
    """Return ``username`` if it is alphanumeric, else ``None``."""
    if not username or not ALNUM_RE.match(username):
        return None
    return username


def _user_paths(username):
    """Return ``(json_path, pass_path)`` rooted at DATA_DIR."""
    json_path = os.path.join(DATA_DIR, f"{username}.json")
    pass_path = os.path.join(DATA_DIR, f"{username}.pass")
    return json_path, pass_path


def _check_password(pass_path, password):
    try:
        with open(pass_path, "r", encoding="utf-8", errors="replace") as fh:
            stored = fh.read().strip()
    except OSError:
        return False
    return stored == password


def _parse_user_data(json_path):
    """Parse the binary's JSON-Lines output, last-write-wins per field."""
    fields = {key: "" for key in FIELD_KEYS}
    try:
        with open(json_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return fields

    for raw in content.split("\n"):
        line = raw.rstrip("\r").strip()
        if not line:
            continue
        match = LINE_RE.match(line)
        if not match:
            continue
        name, value = match.group(1), match.group(2)
        if name in fields:
            fields[name] = value
    return fields


@app.route("/")
def index():
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))
    if _safe_username(username) is None:
        session.clear()
        abort(400)

    json_path, _ = _user_paths(username)
    fields = _parse_user_data(json_path)
    return render_template("index.html", username=username, fields=fields)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = _safe_username(request.form.get("username", "").strip())
        password = request.form.get("password", "")
        if username is None:
            error = "Invalid credentials."
        else:
            json_path, pass_path = _user_paths(username)
            if (
                os.path.isfile(json_path)
                and os.path.isfile(pass_path)
                and _check_password(pass_path, password)
            ):
                session.clear()
                session["username"] = username
                return redirect(url_for("index"))
            error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    port = int(os.environ.get("WEB_PORT", "5000"))
    app.run(host="0.0.0.0", port=port)


