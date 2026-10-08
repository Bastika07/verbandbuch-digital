# Digitales Verbandbuch

Revisionssichere Web-App zur Dokumentation von Arbeitsunfällen und Verletzungen gemäß DGUV Vorschrift 1 § 24.

> **Wichtig:** Dieses Projekt bietet OWASP-orientierte Schutzmaßnahmen (OWASP Top 10, 2021).
> Es handelt sich weder um eine Sicherheitszertifizierung noch um eine Garantie rechtlicher Konformität.
> Der Betreiber ist für den rechtssicheren Einsatz, die organisatorischen Maßnahmen
> und die Einhaltung der DGUV-Vorgaben verantwortlich.

---

## Rechtliche Grundlage

Gemäß **DGUV Vorschrift 1 § 24** muss ein Verbandbuch geführt werden. Es muss:

- manipulationssicher sein
- Einträge dauerhaft und vollständig bewahren (Aufbewahrungspflicht **mind. 5 Jahre**)
- den Datenschutz gewährleisten (keine Einsicht durch Unbefugte)

Ergänzend erforderlich: **Berechtigungskonzept, regelmäßige Backups, Zugriffsschutz auf
Serverebene sowie ein Aufbewahrungs- und Löschkonzept.**

---

## Pflichtfelder

| Feld | Beschreibung |
|---|---|
| Verletzte Person | Name der verletzten Person |
| Datum / Uhrzeit | Zeitpunkt des Unfalls |
| Unfallort | Ort des Unfalls |
| Hergang | Schilderung des Unfallhergangs |
| Art der Verletzung | Art und Ausmaß der Verletzung |
| Ersthelfer | Wer hat Erste Hilfe geleistet? (oder: „Keine") |
| Zeugen | Wer war Zeuge? (oder: „Keine") |

---

## Rollen

| Rolle | Rechte |
|---|---|
| Normaler Nutzer | Formular ausfüllen und absenden – kein Zugriff auf andere Einträge |
| Admin | Login, alle Einträge einsehen, Hash-Kette prüfen, CSV-Export, Nachträge hinzufügen, Passwort ändern |

---

## Technische Revisionssicherheit

### Append-only auf Datenbankebene

SQLite-Trigger verhindern `UPDATE` und `DELETE` auf **entries** und **amendments** direkt
auf Datenbankebene – unabhängig von der Anwendungslogik.

### SHA-256-Hash-Kette

Jeder Eintrag enthält:

```
entry_hash = SHA-256(JSON(alle inhaltlichen Felder + previous_hash))
```

Manipulation eines einzelnen Eintrags bricht die gesamte Kette.
Die Admin-Seite `/admin/verify` prüft Kette und Nachträge auf Knopfdruck.

### Grenzen der technischen Sicherheit

- Die Hash-Kette schützt **nicht** gegen Root-Angreifer, die die gesamte Datenbankdatei
  ersetzen und die Kette neu berechnen. Externe, unveränderliche Checkpoints
  (z. B. täglicher Hash in einem separaten, schreibgeschützten System) werden empfohlen.
- SHA-256 ist **keine Verschlüsselung** – es handelt sich um eine Prüfsumme zur Integritätssicherung.
- SQLite liegt **unverschlüsselt** auf Disk vor. Serverseitige Disk-Verschlüsselung wird empfohlen.

### Nachträge statt Änderungen

Korrekturen sind ausschließlich als unveränderliche, verkettete Nachträge möglich.
Der Original-Eintrag bleibt immer erhalten.

---

## OWASP Top 10 (2021) – Umsetzungsstand

| # | OWASP-Risiko | Maßnahme | Status |
|---|---|---|---|
| A01 | Broken Access Control | Normale Nutzer: ausschließlich `/new` + `/submit`, kein Read-Zugriff auf Einträge. Alle Admin-Routen hinter `@admin_required` mit Session-Versionsprüfung (Passwortänderung invalidiert alle anderen offenen Sessions). | ✅ |
| A02 | Cryptographic Failures | HTTPS vorausgesetzt. `HttpOnly`, `Secure`, `SameSite=Lax` Cookies. Passwort-Hashing via Werkzeug (scrypt). Keine Gesundheitsdaten in externen Systemen. | ✅ |
| A03 | Injection | Ausschließlich parametrisierte SQL-Queries. Jinja2-Autoescaping aktiv. CSV Formula Injection entschärft (Tab-Prefix). Serverseitige Feldlängenlimits. | ✅ |
| A04 | Insecure Design | Append-only durch DB-Trigger (nicht nur App-Logik). Nachträge statt Änderungen. SHA-256-Hash-Kette. Kein Read-Zugriff für normale Nutzer per Design. | ✅ |
| A05 | Security Misconfiguration | CSP (`style-src 'self'`), `X-Frame-Options: DENY`, `nosniff`, `Cache-Control: no-store`. systemd: `DynamicUser`, `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`. `MAX_CONTENT_LENGTH=32 kB`. | ✅ |
| A06 | Vulnerable & Outdated Components | Abhängigkeiten mit festen Versionsbereichen gepinnt. Regelmäßiger Scan mit `pip-audit` empfohlen. | ⚠️ manuell |
| A07 | Identification & Auth Failures | Login-Rate-Limiting (5 Versuche / 15 Min., SQLite-basiert, Multi-Worker-fähig). CSRF-Schutz (Byte-Vergleich via `hmac.compare_digest`). Session-Versionierung bei Passwortänderung. Mindestlänge 15 Zeichen. | ✅ |
| A08 | Software & Data Integrity Failures | SHA-256-Kette, DB-Trigger gegen DELETE/UPDATE, Integritätsprüfung im Admin-Bereich, verkettete Nachträge für Korrekturen. | ✅ |
| A09 | Security Logging & Monitoring | Gunicorn Access-Log aktiv. Kein separates Audit-Log (welcher Admin hat wann welchen Eintrag eingesehen/exportiert). | ⚠️ offen |
| A10 | SSRF | Teams-Webhook ausschließlich über statisch konfigurierte Umgebungsvariable – kein nutzergesteuerter Request, keine Redirects. | ✅ |

---

## Installation

```bash
# 1. Python-Umgebung einrichten
python3 -m venv venv
venv/bin/pip install -r requirements.txt

# 2. Konfiguration anlegen
cp .env.example .env
# SECRET_KEY generieren und in .env eintragen:
python3 -c "import secrets; print(secrets.token_hex(48))"
chmod 600 .env

# 3. Admin-Nutzer anlegen (interaktiv)
SECRET_KEY=<aus .env> DATA_DIR=/var/lib/verbandbuch \
  venv/bin/flask --app app create-admin

# 4. Starten (lokaler Test)
SECRET_KEY=<key> venv/bin/gunicorn --bind 127.0.0.1:8091 wsgi:app
```

---

## Deployment (systemd + Reverse Proxy)

### Dateien auf Server kopieren

```bash
tar czf - \
  --exclude='.git' --exclude='venv' --exclude='data' \
  --exclude='.env' --exclude='__pycache__' . \
  | ssh root@<SERVER> 'mkdir -p /opt/verbandbuch-digital && tar xzf - -C /opt/verbandbuch-digital'
```

### Python-Umgebung & Konfiguration auf dem Server

```bash
ssh root@<SERVER>
cd /opt/verbandbuch-digital
python3 -m venv venv
venv/bin/pip install -r requirements.txt
cp .env.example .env
# .env anpassen: SECRET_KEY, DATA_DIR, SECURE_COOKIES=1, PUBLIC_BASE_URL, TEAMS_WEBHOOK_URL
chmod 600 .env
```

### systemd-Service aktivieren

```bash
cp deploy/verbandbuch-digital.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now verbandbuch-digital
systemctl status verbandbuch-digital
```

### Reverse Proxy

`deploy/apache-vhost.conf.example` enthält eine generische Apache-Vorlage.
`ServerName` und `ServerAdmin` anpassen, dann:

```bash
a2enmod proxy proxy_http
a2ensite verbandbuch
apachectl configtest && systemctl reload apache2
```

**Für Nginx / Nginx Proxy Manager** oder andere Reverse Proxies:
- Ziel: `http://127.0.0.1:8091`
- `X-Forwarded-For` und `X-Forwarded-Proto` müssen weitergeleitet werden
- `ProxyFix` in `app.py` ist auf **einen** Proxy-Hop konfiguriert (`x_for=1, x_proto=1`).
  Bei mehreren Hops (z. B. NPM → Apache → Gunicorn) entsprechend anpassen.

### HTTPS

HTTPS ist Pflicht (`SECURE_COOKIES=1`).
Empfohlen: Let's Encrypt via Certbot oder Nginx Proxy Manager mit automatischer Zertifikatsverwaltung.
HSTS-Header am Reverse Proxy setzen.

---

## Konfiguration (`.env`)

| Variable | Pflicht | Beschreibung |
|---|---|---|
| `SECRET_KEY` | ✅ | Mind. 48 zufällige Hex-Zeichen – niemals ins Repo einchecken |
| `DATA_DIR` | – | Pfad zur SQLite-Datei (Standard: `./data`) |
| `SECURE_COOKIES` | – | `1` bei HTTPS (empfohlen), `0` nur für lokale Tests ohne TLS |
| `PUBLIC_BASE_URL` | – | Öffentliche Basis-URL, z. B. `https://verbandbuch.example.com` (für Admin-Links in Benachrichtigungen) |
| `TEAMS_WEBHOOK_URL` | – | Microsoft Teams Incoming Webhook (leer lassen = deaktiviert) |

---

## Teams-Benachrichtigung (optional)

Bei gesetztem `TEAMS_WEBHOOK_URL` wird nach jedem neuen Eintrag eine Benachrichtigung gesendet.

**Datenschutz:** Es werden **keine** Gesundheitsdaten, Namen, Verletzungen oder Orte übertragen.
Nur Eintrag-ID und ein Admin-Link (wenn `PUBLIC_BASE_URL` gesetzt).

- Fehler beim Versand blockieren die Speicherung **nicht**
- Webhook-URL darf nie in Logs ausgegeben werden
- Nur HTTPS-Endpunkte verwenden
- Für produktiven Betrieb empfiehlt sich ein Outbox-Pattern nach DB-Commit

---

## Offene Punkte / Empfehlungen

- [ ] **Audit-Log**: Wer hat wann welchen Eintrag eingesehen / exportiert?
- [ ] **Externe Checkpoints** für die Hash-Kette (z. B. täglicher Hash in separates, schreibgeschütztes System)
- [ ] **Disk-Verschlüsselung** auf Serverebene
- [ ] **Dependency-Scan** mit `pip-audit` regelmäßig durchführen
- [ ] **Backup-Strategie** und Restore-Tests (Aufbewahrungspflicht mind. 5 Jahre)
- [ ] **HSTS-Header** am Reverse Proxy
- [ ] **Zugriffskonzept** und **Löschkonzept** schriftlich dokumentieren
- [ ] Rate Limiting: ergänzend IP-weites Budget (unabhängig vom Username)

---

## Projektstruktur

```
app.py                          # Flask-App (Routen, Hash-Kette, DB, Rate Limiting, Teams)
wsgi.py                         # Gunicorn-Einstieg
requirements.txt                # Abhängigkeiten (Flask, Gunicorn, Werkzeug)
templates/
  base.html                     # Layout, Admin-Navigation
  form.html                     # Eintragsformular (öffentlich)
  success.html                  # Bestätigung
  login.html                    # Admin-Login
  admin_entries.html            # Eintrags-Übersicht
  admin_entry.html              # Einzel-Eintrag + Nachtrag
  admin_password.html           # Passwort ändern
  admin_verify.html             # Hash-Ketten-Prüfung
static/style.css
deploy/
  verbandbuch-digital.service   # systemd-Unit
  apache-vhost.conf.example     # Apache Reverse-Proxy-Vorlage (generisch)
```
