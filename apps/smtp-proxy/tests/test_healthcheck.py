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
    def test_result_is_written_to_history(self):
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

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "failed")

    def test_settings_load_history_paths_from_env(self):
        with tempfile.TemporaryDirectory() as tempdir:
            history_path = os.path.join(tempdir, "custom-healthcheck.jsonl")

            with mock.patch.dict(
                os.environ,
                {
                    "SMTP_PROXY_HEALTHCHECK_HISTORY_PATH": history_path,
                    "SMTP_PROXY_HEALTHCHECK_HISTORY_MAX_BYTES": "1234",
                },
                clear=True,
            ):
                settings = load_healthcheck_settings_from_env()

        self.assertEqual(settings.history_path, history_path)
        self.assertEqual(settings.history_max_bytes, 1234)

    def test_history_rotates_when_max_bytes_is_reached(self):
        with tempfile.TemporaryDirectory() as tempdir:
            settings = self._settings(tempdir, history_max_bytes=1)
            record_healthcheck_result(settings, self._failed_event("first"))
            record_healthcheck_result(settings, self._failed_event("second"))

            with open(settings.history_path, "r", encoding="utf-8") as history_file:
                current_rows = [json.loads(line) for line in history_file]
            with open(f"{settings.history_path}.1", "r", encoding="utf-8") as rotated_file:
                rotated_rows = [json.loads(line) for line in rotated_file]

        self.assertEqual(current_rows[0]["message"], "healthcheck failed: second")
        self.assertEqual(rotated_rows[0]["message"], "healthcheck failed: first")

    def _settings(self, tempdir, **overrides):
        kwargs = {
            "history_path": os.path.join(tempdir, "healthcheck.jsonl"),
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


if __name__ == "__main__":
    unittest.main()
