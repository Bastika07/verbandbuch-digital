import importlib.util
import json
import os
from pathlib import Path
import smtplib
import tempfile
import unittest
from unittest.mock import patch


class NotificationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.environment = {
            "SECRET_KEY": "test-secret-not-for-production",
            "DATA_DIR": directory.name,
        }
        self.module = self.load_app()

    def load_app(self, **settings):
        spec = importlib.util.spec_from_file_location(
            "notification_test_app", Path(__file__).resolve().parents[1] / "app.py"
        )
        module = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {**self.environment, **settings}, clear=True):
            spec.loader.exec_module(module)
        return module

    def smtp_app(self, **settings):
        return self.load_app(**{
            "NOTIFICATION_METHOD": "smtp",
            "SMTP_HOST": "smtp.example.com",
            "SMTP_FROM": "sender@example.com",
            "SMTP_TO": "first@example.com, second@example.com",
            "PUBLIC_BASE_URL": "https://verbandbuch.example.com/",
            **settings,
        })

    def test_disabled_does_not_connect(self):
        module = self.load_app(
            NOTIFICATION_METHOD="none", WEBHOOK_URL="https://webhook.example.com"
        )
        with patch.object(module, "notify_webhook") as webhook, \
                patch.object(module, "notify_smtp") as smtp:
            module.notify_entry(42)
        webhook.assert_not_called()
        smtp.assert_not_called()

    def test_legacy_teams_configuration(self):
        module = self.load_app(TEAMS_WEBHOOK_URL="https://teams.example.com/hook")
        self.assertEqual(module.NOTIFICATION_METHOD, "webhook")
        self.assertEqual(module.WEBHOOK_URL, "https://teams.example.com/hook")

    def test_webhook_payload_and_url_precedence(self):
        module = self.load_app(
            WEBHOOK_URL="https://webhook.example.com/hook",
            TEAMS_WEBHOOK_URL="https://old.example.com/hook",
            PUBLIC_BASE_URL="https://verbandbuch.example.com/",
        )
        with patch.object(module.urllib.request, "urlopen") as urlopen:
            module.notify_entry(42)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://webhook.example.com/hook")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 3)
        payload = json.loads(request.data)
        self.assertEqual(payload["@type"], "MessageCard")
        self.assertEqual(
            payload["text"],
            "Eintrag **#42** wurde gespeichert.\n\n[Eintrag im Admin-Bereich öffnen]"
            "(https://verbandbuch.example.com/admin/entry/42)",
        )
        urlopen.return_value.__exit__.assert_called_once()

    def test_smtp_starttls_before_login_and_message(self):
        module = self.smtp_app(SMTP_USERNAME="user", SMTP_PASSWORD="secret")
        with patch.object(module.smtplib, "SMTP") as smtp_class, \
                patch.object(module.smtplib, "SMTP_SSL") as ssl_class:
            module.notify_entry(42)
        smtp_class.assert_called_once_with("smtp.example.com", 587, timeout=3)
        ssl_class.assert_not_called()
        smtp = smtp_class.return_value.__enter__.return_value
        self.assertEqual(
            [call[0] for call in smtp.method_calls], ["starttls", "login", "send_message"]
        )
        smtp.login.assert_called_once_with("user", "secret")
        message = smtp.send_message.call_args.args[0]
        self.assertEqual(str(message["Subject"]), "Neuer Verbandbuch-Eintrag")
        self.assertEqual(str(message["From"]), "sender@example.com")
        self.assertEqual(
            message.get_content(),
            "Eintrag #42 wurde gespeichert.\n\nEintrag im Admin-Bereich öffnen:\n"
            "https://verbandbuch.example.com/admin/entry/42\n",
        )
        self.assertEqual(
            smtp.send_message.call_args.kwargs["to_addrs"],
            ["first@example.com", "second@example.com"],
        )

    def test_smtp_implicit_tls(self):
        module = self.smtp_app(SMTP_SECURITY="ssl")
        with patch.object(module.smtplib, "SMTP_SSL") as ssl_class, \
                patch.object(module.smtplib, "SMTP") as smtp_class:
            module.notify_entry(42)
        smtp_class.assert_not_called()
        self.assertEqual(ssl_class.call_args.args, ("smtp.example.com", 465))
        self.assertIn("context", ssl_class.call_args.kwargs)
        smtp = ssl_class.return_value.__enter__.return_value
        smtp.starttls.assert_not_called()
        smtp.login.assert_not_called()
        smtp.send_message.assert_called_once()

    def test_starttls_failure_never_sends_credentials_or_message(self):
        module = self.smtp_app(SMTP_USERNAME="user", SMTP_PASSWORD="secret")
        with patch.object(module.smtplib, "SMTP") as smtp_class, \
                self.assertLogs(module.app.logger, level="WARNING"):
            smtp = smtp_class.return_value.__enter__.return_value
            smtp.starttls.side_effect = smtplib.SMTPNotSupportedError("No STARTTLS")
            module.notify_entry(42)
        smtp.login.assert_not_called()
        smtp.send_message.assert_not_called()

    def test_webhook_without_public_url(self):
        module = self.load_app(WEBHOOK_URL="https://webhook.example.com/hook")
        with patch.object(module.urllib.request, "urlopen") as urlopen:
            module.notify_entry(42)
        self.assertEqual(
            json.loads(urlopen.call_args.args[0].data)["text"],
            "Eintrag **#42** wurde gespeichert.",
        )

    def test_relay_without_tls_or_login_and_without_link(self):
        module = self.smtp_app(SMTP_SECURITY="none", PUBLIC_BASE_URL="")
        with patch.object(module.smtplib, "SMTP") as smtp_class:
            module.notify_entry(42)
        smtp = smtp_class.return_value.__enter__.return_value
        smtp.starttls.assert_not_called()
        smtp.login.assert_not_called()
        self.assertEqual(
            smtp.send_message.call_args.args[0].get_content(),
            "Eintrag #42 wurde gespeichert.\n",
        )

    def test_invalid_configuration_rejected(self):
        for settings in [
            {"NOTIFICATION_METHOD": "invalid"},
            {"NOTIFICATION_METHOD": "webhook"},
            {"NOTIFICATION_METHOD": "smtp"},
        ]:
            with self.subTest(settings=settings), self.assertRaises(RuntimeError):
                self.load_app(**settings)
        for settings in [
            {"SMTP_SECURITY": "invalid"},
            {"SMTP_PORT": "0"},
            {"SMTP_USERNAME": "user"},
            {"SMTP_PASSWORD": "secret"},
            {"SMTP_USERNAME": "user", "SMTP_PASSWORD": "secret", "SMTP_SECURITY": "none"},
        ]:
            with self.subTest(settings=settings), self.assertRaises(RuntimeError):
                self.smtp_app(**settings)

    def test_delivery_errors_do_not_leak_secrets(self):
        for method in ["smtp", "webhook"]:
            with self.subTest(method=method), \
                    patch.object(self.module, "NOTIFICATION_METHOD", method), \
                    patch.object(self.module, f"notify_{method}",
                                 side_effect=OSError("sensitive-url-or-password")), \
                    self.assertLogs(self.module.app.logger, level="WARNING") as logs:
                self.module.notify_entry(42)
            self.assertNotIn("sensitive-url-or-password", "\n".join(logs.output))

    def test_smtp_failure_still_commits_entry(self):
        module = self.smtp_app()
        client = module.app.test_client()
        with client.session_transaction() as session:
            session["csrf"] = "test-csrf"
        form = {field: "sensitive-form-data" for field in module.FIELD_LIMITS}
        form.update(csrf_token="test-csrf", incident_dt="2026-10-26T12:00")
        with patch.object(module.smtplib, "SMTP", side_effect=smtplib.SMTPException("secret")), \
                self.assertLogs(module.app.logger, level="WARNING") as logs:
            response = client.post("/submit", data=form)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/success")
        self.assertNotIn("secret", "\n".join(logs.output))
        with module.app.app_context():
            rows = module.get_db().execute("SELECT * FROM entries").fetchall()
            self.assertEqual(len(rows), 1)
            self.assertTrue(module.verify_chain(rows)[0])


if __name__ == "__main__":
    unittest.main()
