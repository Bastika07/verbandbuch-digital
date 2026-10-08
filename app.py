#!/usr/bin/env python3
"""
Digitales Verbandbuch – revisionssichere Webapp
================================================
Anforderungen:
  • Append-only (SQLite-Trigger verhindern UPDATE/DELETE)
  • Hash-Kette: jeder Eintrag enthält SHA-256(Felder + prev_hash)
  • Rollentrennung: anonymes Eintragen vs. Admin-Zugang
  • CSRF-Schutz, Security-Headers, kein JS nötig
"""
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from functools import wraps

from flask import (Flask, abort, flash, g, make_response, redirect,
                   render_template, request, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# ── Konfiguration ─────────────────────────────────────────────────────────────
BASE_DIR          = os.path.dirname(os.path.abspath(__file__))
DATA_DIR          = os.environ.get("DATA_DIR",          os.path.join(BASE_DIR, "data"))
SECRET_KEY        = os.environ.get("SECRET_KEY",        "")
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
PUBLIC_BASE_URL   = os.environ.get("PUBLIC_BASE_URL",   "").strip()

if not SECRET_KEY:
    raise RuntimeError("Umgebungsvariable SECRET_KEY muss gesetzt sein.")

os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "verbandbuch.sqlite")

# ── Feldlimits (serverseitig) ─────────────────────────────────────────────────
FIELD_LIMITS = {
    "injured_person": 200,
    "incident_dt":    32,
    "location":       300,
    "description":    2000,
    "injury_type":    500,
    "witnesses":      500,
    "first_aiders":   500,
}

# ── Login Rate Limiting ───────────────────────────────────────────────────────
LOGIN_WINDOW   = 15 * 60  # Sekunden
LOGIN_MAX_FAIL = 5         # Fehlversuche pro Username+IP im Fenster

app = Flask(__name__)
# NPM → Gunicorn: ein Proxy-Hop (kein x_host – verhindert Host-Spoofing)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SECURE_COOKIES", "0") == "1",
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=32 * 1024,   # 32 kB – kein übermäßig großes POST
)

# ── Datenbankschema ───────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at       TEXT    NOT NULL,
    injured_person   TEXT    NOT NULL,
    incident_dt      TEXT    NOT NULL,
    location         TEXT    NOT NULL,
    description      TEXT    NOT NULL,
    injury_type      TEXT    NOT NULL,
    witnesses        TEXT    NOT NULL,
    first_aiders     TEXT    NOT NULL,
    previous_hash    TEXT    NOT NULL DEFAULT '',
    entry_hash       TEXT    NOT NULL
);

CREATE TRIGGER IF NOT EXISTS trg_no_update_entries
BEFORE UPDATE ON entries BEGIN
    SELECT RAISE(ABORT, 'Eintraege sind unveraenderlich.');
END;

CREATE TRIGGER IF NOT EXISTS trg_no_delete_entries
BEFORE DELETE ON entries BEGIN
    SELECT RAISE(ABORT, 'Eintraege duerfen nicht geloescht werden.');
END;

CREATE TABLE IF NOT EXISTS amendments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id        INTEGER NOT NULL REFERENCES entries(id),
    created_at      TEXT    NOT NULL,
    reason          TEXT    NOT NULL,
    amendment_text  TEXT    NOT NULL,
    amended_by      TEXT    NOT NULL,
    previous_hash   TEXT    NOT NULL,
    amendment_hash  TEXT    NOT NULL
);

CREATE TRIGGER IF NOT EXISTS trg_no_update_amendments
BEFORE UPDATE ON amendments BEGIN
    SELECT RAISE(ABORT, 'Nachtraege sind unveraenderlich.');
END;

CREATE TRIGGER IF NOT EXISTS trg_no_delete_amendments
BEFORE DELETE ON amendments BEGIN
    SELECT RAISE(ABORT, 'Nachtraege duerfen nicht geloescht werden.');
END;

CREATE TABLE IF NOT EXISTS admins (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    UNIQUE NOT NULL,
    password_hash   TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    session_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT    NOT NULL,
    ip           TEXT    NOT NULL,
    attempted_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_attempts
ON login_attempts(username, ip, attempted_at);
"""

# Migrationen für bestehende Datenbanken (idempotent)
MIGRATIONS = [
    "ALTER TABLE admins ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0",
    ("CREATE TABLE IF NOT EXISTS login_attempts ("
     "id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, "
     "ip TEXT NOT NULL, attempted_at INTEGER NOT NULL)"),
    ("CREATE INDEX IF NOT EXISTS idx_login_attempts "
     "ON login_attempts(username, ip, attempted_at)"),
]


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    for stmt in MIGRATIONS:
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError:
            pass   # Spalte/Index existiert bereits
    conn.commit()
    conn.close()


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


# Datenbank beim ersten Start anlegen
init_db()

# ── Login Rate Limiting (SQLite, Multi-Worker-fähig) ─────────────────────────
def client_ip() -> str:
    return request.remote_addr or "unknown"


def login_is_blocked(db, username: str, ip: str) -> bool:
    now    = int(time.time())
    cutoff = now - LOGIN_WINDOW
    db.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (cutoff,))
    row = db.execute(
        "SELECT COUNT(*) AS c FROM login_attempts "
        "WHERE username = ? AND ip = ? AND attempted_at >= ?",
        (username, ip, cutoff),
    ).fetchone()
    return row["c"] >= LOGIN_MAX_FAIL


def record_login_fail(db, username: str, ip: str) -> None:
    db.execute(
        "INSERT INTO login_attempts (username, ip, attempted_at) VALUES (?,?,?)",
        (username, ip, int(time.time())),
    )


def clear_login_attempts(db, username: str, ip: str) -> None:
    db.execute(
        "DELETE FROM login_attempts WHERE username = ? AND ip = ?",
        (username, ip),
    )


# ── Teams-Webhook (optional, keine Gesundheitsdaten) ─────────────────────────
def notify_teams(entry_id: int) -> None:
    """
    Sendet eine anonymisierte Benachrichtigung an Microsoft Teams.
    Enthält ausschließlich Eintrag-ID + Admin-Link – keine Namen,
    Verletzungen, Orte oder sonstige personenbezogene/Gesundheitsdaten.
    Wird übersprungen wenn TEAMS_WEBHOOK_URL nicht gesetzt ist.
    Fehler blockieren die Speicherung NICHT.
    """
    if not TEAMS_WEBHOOK_URL:
        return
    link = ""
    if PUBLIC_BASE_URL:
        link = (f"\n\n[Eintrag im Admin-Bereich öffnen]"
                f"({PUBLIC_BASE_URL.rstrip('/')}/admin/entry/{entry_id})")
    payload = json.dumps({
        "@type":      "MessageCard",
        "@context":   "http://schema.org/extensions",
        "summary":    "Neuer Verbandbuch-Eintrag",
        "themeColor": "0076D7",
        "title":      "🩹 Neuer Verbandbuch-Eintrag erfasst",
        "text":       f"Eintrag **#{entry_id}** wurde gespeichert.{link}",
    }).encode("utf-8")
    req = urllib.request.Request(
        TEAMS_WEBHOOK_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=3).read()
    except Exception:
        app.logger.warning("Teams-Benachrichtigung fehlgeschlagen", exc_info=True)


# ── Hash-Kette ────────────────────────────────────────────────────────────────
def compute_entry_hash(fields: dict, previous_hash: str) -> str:
    """SHA-256 über alle inhaltlichen Felder + previous_hash."""
    payload = json.dumps({
        "created_at":     fields["created_at"],
        "injured_person": fields["injured_person"],
        "incident_dt":    fields["incident_dt"],
        "location":       fields["location"],
        "description":    fields["description"],
        "injury_type":    fields["injury_type"],
        "witnesses":      fields["witnesses"],
        "first_aiders":   fields["first_aiders"],
        "previous_hash":  previous_hash,
    }, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_amendment_hash(fields: dict, previous_hash: str) -> str:
    """SHA-256 über alle inhaltlichen Felder eines Nachtrags + previous_hash."""
    payload = json.dumps({
        "entry_id":   fields["entry_id"],
        "created_at": fields["created_at"],
        "reason":     fields["reason"],
        "text":       fields["amendment_text"],
        "by":         fields["amended_by"],
        "prev":       previous_hash,
    }, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_chain(entries, amendments_by_entry: dict | None = None) -> tuple:
    errors = []
    prev_hash = ""
    for row in entries:
        d = dict(row)
        # Gespeicherter previous_hash muss zum Vorgänger passen
        if d["previous_hash"] != prev_hash:
            errors.append(
                f"Eintrag #{d['id']} ({d['created_at']}): "
                "previous_hash stimmt nicht mit Vorgänger-Hash überein."
            )
        expected = compute_entry_hash(d, d["previous_hash"])
        if not hmac.compare_digest(expected, d["entry_hash"]):
            errors.append(
                f"Eintrag #{d['id']} ({d['created_at']}): "
                "entry_hash stimmt nicht überein – mögliche Manipulation!"
            )
        prev_hash = d["entry_hash"]
        # Nachträge zu diesem Eintrag prüfen
        if amendments_by_entry:
            a_prev = d["entry_hash"]
            for a in amendments_by_entry.get(d["id"], []):
                ad = dict(a)
                if ad["previous_hash"] != a_prev:
                    errors.append(
                        f"Nachtrag #{ad['id']} zu Eintrag #{d['id']}: "
                        "previous_hash stimmt nicht überein."
                    )
                expected_a = compute_amendment_hash(ad, ad["previous_hash"])
                if not hmac.compare_digest(expected_a, ad["amendment_hash"]):
                    errors.append(
                        f"Nachtrag #{ad['id']} zu Eintrag #{d['id']}: "
                        "amendment_hash stimmt nicht überein – mögliche Manipulation!"
                    )
                a_prev = ad["amendment_hash"]
    return len(errors) == 0, errors


# ── CSRF ──────────────────────────────────────────────────────────────────────
def get_csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(32)
    return session["csrf"]


def csrf_protect():
    tok = request.form.get("csrf_token", "")
    expected = session.get("csrf", "")
    if not tok or not expected:
        abort(403)
    try:
        if not hmac.compare_digest(tok.encode("utf-8"), expected.encode("utf-8")):
            abort(403)
    except Exception:
        abort(403)


app.jinja_env.globals["csrf_token"] = get_csrf_token

# ── Security-Headers ──────────────────────────────────────────────────────────
@app.after_request
def set_security_headers(resp):
    resp.headers.update({
        "X-Frame-Options":        "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy":        "no-referrer",
        "Cache-Control":          "no-store, no-cache",
        "Content-Security-Policy": (
            "default-src 'none'; "
            "style-src 'self'; "
            "form-action 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'"
        ),
    })
    return resp


# ── Auth-Decorator mit Session-Versionsprüfung ────────────────────────────────
def admin_required(f):
    @wraps(f)
    def deco(*args, **kwargs):
        if not session.get("is_admin") or "admin_user" not in session:
            return redirect(url_for("admin_login"))
        # Passwortänderung erhöht session_version → laufende fremde Sessions ungültig
        db  = get_db()
        row = db.execute(
            "SELECT session_version FROM admins WHERE username = ?",
            (session["admin_user"],),
        ).fetchone()
        if not row or row["session_version"] != session.get("admin_version"):
            session.clear()
            flash("Sitzung abgelaufen. Bitte neu anmelden.", "error")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return deco


# ── Öffentliche Routen (normaler Nutzer: nur eintragen) ───────────────────────
@app.route("/")
def index():
    return redirect(url_for("new_entry"))


@app.route("/new")
def new_entry():
    now_local = datetime.now().strftime("%Y-%m-%dT%H:%M")
    return render_template("form.html", now=now_local, values={}, errors=[])


@app.route("/submit", methods=["POST"])
def submit_entry():
    csrf_protect()

    values = {f: request.form.get(f, "").strip() for f in FIELD_LIMITS}
    errors = []
    for field, max_len in FIELD_LIMITS.items():
        v = values[field]
        if not v:
            errors.append(field)
        elif len(v) > max_len:
            errors.append(field)

    # Datum/Uhrzeit serverseitig parsen
    if "incident_dt" not in errors and values.get("incident_dt"):
        try:
            datetime.strptime(values["incident_dt"], "%Y-%m-%dT%H:%M")
        except ValueError:
            errors.append("incident_dt")

    if errors:
        flash("Bitte alle Pflichtfelder korrekt ausfüllen.", "error")
        return render_template(
            "form.html",
            now=datetime.now().strftime("%Y-%m-%dT%H:%M"),
            values=values,
            errors=errors,
        ), 422

    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    values["created_at"] = created_at

    db = get_db()
    entry_id = None
    try:
        db.execute("BEGIN IMMEDIATE")
        last = db.execute(
            "SELECT entry_hash FROM entries ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev = last["entry_hash"] if last else ""
        entry_hash = compute_entry_hash(values, prev)
        cur = db.execute(
            "INSERT INTO entries "
            "(created_at, injured_person, incident_dt, location, description, "
            " injury_type, witnesses, first_aiders, previous_hash, entry_hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                created_at, values["injured_person"], values["incident_dt"],
                values["location"], values["description"], values["injury_type"],
                values["witnesses"], values["first_aiders"], prev, entry_hash,
            ),
        )
        entry_id = cur.lastrowid
        db.execute("COMMIT")
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise

    notify_teams(entry_id)
    return redirect(url_for("success"))


@app.route("/success")
def success():
    return render_template("success.html")


# ── Admin-Login / -Logout ─────────────────────────────────────────────────────
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        csrf_protect()
        user = request.form.get("username", "").strip()
        pw   = request.form.get("password", "")
        ip   = client_ip()
        db   = get_db()

        if login_is_blocked(db, user, ip):
            db.commit()
            flash("Zu viele fehlgeschlagene Anmeldeversuche. Bitte später erneut versuchen.", "error")
            return render_template("login.html"), 429

        row = db.execute(
            "SELECT password_hash, session_version FROM admins WHERE username = ?", (user,)
        ).fetchone()

        if row and check_password_hash(row["password_hash"], pw):
            clear_login_attempts(db, user, ip)
            db.commit()
            session.clear()
            session["is_admin"]      = True
            session["admin_user"]    = user
            session["admin_version"] = row["session_version"]
            session.permanent        = True
            return redirect(url_for("admin_entries"))

        record_login_fail(db, user, ip)
        db.commit()
        flash("Ungültige Zugangsdaten.", "error")
    return render_template("login.html")


@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    csrf_protect()
    session.clear()
    return redirect(url_for("admin_login"))


# ── Admin: Passwort ändern ────────────────────────────────────────────────────
@app.route("/admin/password", methods=["GET", "POST"])
@admin_required
def admin_password():
    if request.method == "POST":
        csrf_protect()
        ip         = client_ip()
        current_pw = request.form.get("current_password", "")
        new_pw     = request.form.get("new_password", "")
        new_pw2    = request.form.get("new_password2", "")
        db         = get_db()

        if login_is_blocked(db, session["admin_user"], ip):
            db.commit()
            flash("Zu viele Versuche. Bitte später erneut versuchen.", "error")
            return render_template("admin_password.html"), 429
        db.commit()  # DELETE-Cleanup aus login_is_blocked abschließen

        if len(new_pw) < 15:
            flash("Das neue Passwort muss mindestens 15 Zeichen lang sein.", "error")
            return render_template("admin_password.html"), 422

        if len(new_pw) > 128:
            flash("Das neue Passwort darf maximal 128 Zeichen lang sein.", "error")
            return render_template("admin_password.html"), 422

        if new_pw != new_pw2:
            flash("Die neuen Passwörter stimmen nicht überein.", "error")
            return render_template("admin_password.html"), 422

        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT password_hash FROM admins WHERE username = ?",
                (session["admin_user"],),
            ).fetchone()
            if not row or not check_password_hash(row["password_hash"], current_pw):
                record_login_fail(db, session["admin_user"], ip)
                db.execute("COMMIT")
                flash("Aktuelles Passwort ist falsch.", "error")
                return render_template("admin_password.html"), 403

            # session_version erhöhen → alle anderen offenen Sessions werden ungültig
            db.execute(
                "UPDATE admins "
                "SET password_hash = ?, session_version = session_version + 1 "
                "WHERE username = ?",
                (generate_password_hash(new_pw), session["admin_user"]),
            )
            db.execute("COMMIT")
        except Exception:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise

        clear_login_attempts(db, session["admin_user"], ip)
        db.commit()
        session.clear()
        flash("Passwort erfolgreich geändert. Bitte neu anmelden.", "success")
        return redirect(url_for("admin_login"))

    return render_template("admin_password.html")


# ── Admin: Eintrags-Liste ─────────────────────────────────────────────────────
@app.route("/admin/")
@admin_required
def admin_entries():
    db = get_db()
    entries = db.execute(
        "SELECT id, created_at, injured_person, incident_dt, location, injury_type "
        "FROM entries ORDER BY id DESC"
    ).fetchall()
    return render_template("admin_entries.html", entries=entries)


# ── Admin: Einzel-Eintrag ─────────────────────────────────────────────────────
@app.route("/admin/entry/<int:eid>")
@admin_required
def admin_entry(eid):
    db = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id = ?", (eid,)).fetchone()
    if not entry:
        abort(404)
    amendments = db.execute(
        "SELECT * FROM amendments WHERE entry_id = ? ORDER BY id", (eid,)
    ).fetchall()
    return render_template("admin_entry.html", entry=entry, amendments=amendments)


# ── Admin: Nachtrag hinzufügen ────────────────────────────────────────────────
@app.route("/admin/entry/<int:eid>/amend", methods=["POST"])
@admin_required
def admin_amend(eid):
    csrf_protect()
    reason = request.form.get("reason", "").strip()
    text   = request.form.get("amendment_text", "").strip()
    if not reason or not text:
        flash("Begründung und Nachtragstext sind Pflichtfelder.", "error")
        return redirect(url_for("admin_entry", eid=eid))

    db = get_db()
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        db.execute("BEGIN IMMEDIATE")
        last_amend = db.execute(
            "SELECT amendment_hash FROM amendments WHERE entry_id = ? ORDER BY id DESC LIMIT 1",
            (eid,),
        ).fetchone()
        if last_amend:
            prev = last_amend["amendment_hash"]
        else:
            orig = db.execute("SELECT entry_hash FROM entries WHERE id = ?", (eid,)).fetchone()
            if not orig:
                db.execute("ROLLBACK")
                abort(404)
            prev = orig["entry_hash"]

        ahash = compute_amendment_hash(
            {"entry_id": eid, "created_at": created_at, "reason": reason,
             "amendment_text": text, "amended_by": session["admin_user"]},
            prev,
        )
        db.execute(
            "INSERT INTO amendments "
            "(entry_id, created_at, reason, amendment_text, amended_by, "
            " previous_hash, amendment_hash) VALUES (?,?,?,?,?,?,?)",
            (eid, created_at, reason, text, session["admin_user"], prev, ahash),
        )
        db.execute("COMMIT")
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    flash("Nachtrag erfolgreich gespeichert.", "success")
    return redirect(url_for("admin_entry", eid=eid))


# ── Admin: Hash-Kette prüfen ──────────────────────────────────────────────────
@app.route("/admin/verify")
@admin_required
def admin_verify():
    db = get_db()
    entries = db.execute("SELECT * FROM entries ORDER BY id").fetchall()
    all_amendments = db.execute("SELECT * FROM amendments ORDER BY entry_id, id").fetchall()
    amendments_by_entry: dict = {}
    for a in all_amendments:
        amendments_by_entry.setdefault(a["entry_id"], []).append(a)
    ok, errors = verify_chain(entries, amendments_by_entry)
    return render_template(
        "admin_verify.html", ok=ok, errors=errors,
        count=len(entries), amend_count=len(all_amendments),
    )


# ── Admin: CSV-Export ─────────────────────────────────────────────────────────
@app.route("/admin/export.csv")
@admin_required
def admin_export():
    db = get_db()
    rows = db.execute("SELECT * FROM entries ORDER BY id").fetchall()
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow([
        "ID", "Erfasst am (UTC)", "Verletzte Person", "Unfall Datum/Uhrzeit",
        "Ort", "Hergang", "Art der Verletzung", "Zeugen", "Ersthelfer",
        "SHA-256", "Vorheriger SHA-256",
    ])
    for r in rows:
        # Tab-Prefix verhindert Formula-Injection in Excel
        def safe(v):
            s = str(v)
            return ("\t" + s) if s and s[0] in "=+-@" else s
        w.writerow([
            r["id"], r["created_at"], safe(r["injured_person"]),
            r["incident_dt"], safe(r["location"]), safe(r["description"]),
            safe(r["injury_type"]), safe(r["witnesses"]), safe(r["first_aiders"]),
            r["entry_hash"], r["previous_hash"],
        ])
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"]        = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = 'attachment; filename="verbandbuch_export.csv"'
    return resp


# ── CLI: Admin-Nutzer anlegen ─────────────────────────────────────────────────
@app.cli.command("create-admin")
def create_admin_cmd():
    import getpass
    username = input("Benutzername: ").strip()
    password = getpass.getpass("Passwort: ")
    if not username or not password:
        print("Abgebrochen.")
        return
    init_db()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO admins (username, password_hash, created_at, session_version) "
            "VALUES (?,?,?,0)",
            (
                username,
                generate_password_hash(password),
                datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            ),
        )
        conn.commit()
        print(f"Admin '{username}' erfolgreich angelegt.")
    except sqlite3.IntegrityError:
        print(f"Fehler: Benutzername '{username}' existiert bereits.")
    finally:
        conn.close()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8091, debug=False)
