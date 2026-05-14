import os
import sys
import tempfile
import unittest
from unittest import mock

APP_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
CORE_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "alias-routing-core", "src")
sys.path.insert(0, os.path.abspath(APP_SRC))
sys.path.insert(0, os.path.abspath(CORE_SRC))

from sl_smtp_proxy.config import SecretFileError, load_config_from_env


class ConfigLoadingTests(unittest.TestCase):
    def test_existing_env_secret_values_keep_working(self):
        with mock.patch.dict(
            os.environ,
            {
                "SIMPLELOGIN_API_KEY": "env-api-key",
                "SMTP_PROXY_PASSWORD": "env-smtp-password",
                "UPSTREAM_SMTP_PASSWORD": "env-upstream-password",
            },
            clear=True,
        ):
            config = load_config_from_env()

        self.assertEqual(config.simplelogin_api_key, "env-api-key")
        self.assertEqual(config.password, "env-smtp-password")
        self.assertEqual(config.upstream_password, "env-upstream-password")

    def test_secret_file_values_load_into_config_fields(self):
        with tempfile.TemporaryDirectory() as tempdir:
            api_key_file = os.path.join(tempdir, "simplelogin-api-key")
            smtp_password_file = os.path.join(tempdir, "smtp-proxy-password")
            upstream_password_file = os.path.join(tempdir, "upstream-smtp-password")
            self._write(api_key_file, "file-api-key\n")
            self._write(smtp_password_file, "file-smtp-password \n")
            self._write(upstream_password_file, "file-upstream-password\r\n\r\n")

            with mock.patch.dict(
                os.environ,
                {
                    "SIMPLELOGIN_API_KEY_FILE": api_key_file,
                    "SMTP_PROXY_PASSWORD_FILE": smtp_password_file,
                    "UPSTREAM_SMTP_PASSWORD_FILE": upstream_password_file,
                },
                clear=True,
            ):
                config = load_config_from_env()

        self.assertEqual(config.simplelogin_api_key, "file-api-key")
        self.assertEqual(config.password, "file-smtp-password ")
        self.assertEqual(config.upstream_password, "file-upstream-password")

    def test_direct_env_secret_takes_precedence_over_file_value(self):
        with tempfile.TemporaryDirectory() as tempdir:
            api_key_file = os.path.join(tempdir, "simplelogin-api-key")
            smtp_password_file = os.path.join(tempdir, "smtp-proxy-password")
            upstream_password_file = os.path.join(tempdir, "upstream-smtp-password")
            self._write(api_key_file, "file-api-key\n")
            self._write(smtp_password_file, "file-smtp-password\n")
            self._write(upstream_password_file, "file-upstream-password\n")

            with mock.patch.dict(
                os.environ,
                {
                    "SIMPLELOGIN_API_KEY": "env-api-key",
                    "SIMPLELOGIN_API_KEY_FILE": api_key_file,
                    "SMTP_PROXY_PASSWORD": "env-smtp-password",
                    "SMTP_PROXY_PASSWORD_FILE": smtp_password_file,
                    "UPSTREAM_SMTP_PASSWORD": "env-upstream-password",
                    "UPSTREAM_SMTP_PASSWORD_FILE": upstream_password_file,
                },
                clear=True,
            ):
                config = load_config_from_env()

        self.assertEqual(config.simplelogin_api_key, "env-api-key")
        self.assertEqual(config.password, "env-smtp-password")
        self.assertEqual(config.upstream_password, "env-upstream-password")

    def test_direct_env_secret_precedence_does_not_read_missing_file(self):
        with mock.patch.dict(
            os.environ,
            {
                "SMTP_PROXY_PASSWORD": "env-smtp-password",
                "SMTP_PROXY_PASSWORD_FILE": "/path/that/does/not/exist",
            },
            clear=True,
        ):
            config = load_config_from_env()

        self.assertEqual(config.password, "env-smtp-password")

    def test_empty_direct_env_secret_falls_back_to_file(self):
        with tempfile.TemporaryDirectory() as tempdir:
            smtp_password_file = os.path.join(tempdir, "smtp-proxy-password")
            self._write(smtp_password_file, "file-smtp-password\n")

            with mock.patch.dict(
                os.environ,
                {
                    "SMTP_PROXY_PASSWORD": "",
                    "SMTP_PROXY_PASSWORD_FILE": smtp_password_file,
                },
                clear=True,
            ):
                config = load_config_from_env()

        self.assertEqual(config.password, "file-smtp-password")

    def test_missing_secret_file_raises_redacted_error(self):
        with mock.patch.dict(
            os.environ,
            {"SIMPLELOGIN_API_KEY_FILE": "/path/that/does/not/exist"},
            clear=True,
        ):
            with self.assertRaises(SecretFileError) as raised:
                load_config_from_env()

        message = str(raised.exception)
        self.assertIn("SIMPLELOGIN_API_KEY_FILE", message)
        self.assertNotIn("api-key", message)
        self.assertNotIn("SMTP_PROXY_PASSWORD", message)

    def _write(self, path, value):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(value)


if __name__ == "__main__":
    unittest.main()
