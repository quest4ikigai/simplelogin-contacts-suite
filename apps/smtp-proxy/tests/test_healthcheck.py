import json
import os
import sys
import tempfile
import unittest
from unittest import mock

APP_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
CORE_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "alias-routing-core", "src")
sys.path.insert(0, os.path.abspath(APP_SRC))
sys.path.insert(0, os.path.abspath(CORE_SRC))

from sl_smtp_proxy.healthcheck import HealthcheckSettings, load_healthcheck_settings_from_env, record_healthcheck_result


class HealthcheckHistoryTests(unittest.TestCase):
    def test_result_is_written_to_history_and_failure_state(self):
        with tempfile.TemporaryDirectory() as tempdir:
            settings = self._settings(tempdir)

            record_healthcheck_result(
                settings,
                {
                    "timestamp": "2026-05-26T12:00:00Z",
                    "status": "failed",
                    "exit_code": 1,
                    "message": "healthcheck failed: ConnectionRefusedError",
                },
            )

            with open(settings.history_path, "r", encoding="utf-8") as history_file:
                rows = [json.loads(line) for line in history_file]
            with open(settings.state_path, "r", encoding="utf-8") as state_file:
                state = json.load(state_file)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "failed")
        self.assertEqual(rows[0]["consecutive_failures"], 1)
        self.assertEqual(state["consecutive_failures"], 1)

    def test_pushover_alert_is_sent_once_then_recovery_is_sent(self):
        sent = []

        def fake_sender(settings, title, message):
            sent.append((title, message))

        with tempfile.TemporaryDirectory() as tempdir:
            settings = self._settings(
                tempdir,
                alert_after_failures=2,
                pushover_enabled=True,
                pushover_app_token="app-token",
                pushover_user_key="user-key",
            )

            record_healthcheck_result(settings, self._failed_event("first"), alert_sender=fake_sender)
            record_healthcheck_result(settings, self._failed_event("second"), alert_sender=fake_sender)
            record_healthcheck_result(settings, self._failed_event("third"), alert_sender=fake_sender)
            record_healthcheck_result(
                settings,
                {
                    "timestamp": "2026-05-26T12:03:00Z",
                    "status": "ok",
                    "exit_code": 0,
                    "message": "healthcheck ok",
                },
                alert_sender=fake_sender,
            )

        self.assertEqual(len(sent), 2)
        self.assertIn("failed 2 consecutive times", sent[0][1])
        self.assertIn("recovered", sent[1][1])

    def test_settings_support_secret_files_for_pushover_credentials(self):
        with tempfile.TemporaryDirectory() as tempdir:
            token_file = os.path.join(tempdir, "pushover-token")
            user_file = os.path.join(tempdir, "pushover-user")
            self._write(token_file, "file-app-token\n")
            self._write(user_file, "file-user-key\n")

            with mock.patch.dict(
                os.environ,
                {
                    "SMTP_PROXY_HEALTHCHECK_PUSHOVER_ENABLED": "true",
                    "PUSHOVER_APP_TOKEN_FILE": token_file,
                    "PUSHOVER_USER_KEY_FILE": user_file,
                    "PUSHOVER_DEVICE": "phone",
                },
                clear=True,
            ):
                settings = load_healthcheck_settings_from_env()

        self.assertTrue(settings.pushover_enabled)
        self.assertEqual(settings.pushover_app_token, "file-app-token")
        self.assertEqual(settings.pushover_user_key, "file-user-key")
        self.assertEqual(settings.pushover_device, "phone")

    def test_bad_pushover_secret_file_does_not_raise_during_settings_load(self):
        with mock.patch.dict(
            os.environ,
            {
                "SMTP_PROXY_HEALTHCHECK_PUSHOVER_ENABLED": "true",
                "PUSHOVER_APP_TOKEN_FILE": "/path/that/does/not/exist",
            },
            clear=True,
        ):
            settings = load_healthcheck_settings_from_env()

        self.assertTrue(settings.pushover_enabled)
        self.assertIn("PUSHOVER_APP_TOKEN_FILE", settings.pushover_config_error)

    def _settings(self, tempdir, **overrides):
        kwargs = {
            "history_path": os.path.join(tempdir, "healthcheck.jsonl"),
            "state_path": os.path.join(tempdir, "healthcheck-state.json"),
        }
        kwargs.update(overrides)
        return HealthcheckSettings(**kwargs)

    def _failed_event(self, detail):
        return {
            "timestamp": "2026-05-26T12:00:00Z",
            "status": "failed",
            "exit_code": 1,
            "message": f"healthcheck failed: {detail}",
        }

    def _write(self, path, value):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(value)


if __name__ == "__main__":
    unittest.main()
