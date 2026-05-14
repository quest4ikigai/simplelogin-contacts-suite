import os
import sys
import unittest
from unittest import mock

APP_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
CORE_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "alias-routing-core", "src")
sys.path.insert(0, os.path.abspath(APP_SRC))
sys.path.insert(0, os.path.abspath(CORE_SRC))

from sl_smtp_proxy.config import SmtpProxyConfig, load_config_from_env
from sl_smtp_proxy.config_validation import (
    StartupConfigError,
    is_local_development_bind,
    validate_startup_config,
)


def safe_remote_config(**overrides):
    values = {
        "host": "0.0.0.0",
        "require_auth": True,
        "require_tls": True,
        "username": "smtp-user",
        "password": "strong-password",
        "user_mailboxes": {"sender@example.com"},
        "allow_direct_external_send": False,
    }
    values.update(overrides)
    return SmtpProxyConfig(**values)


class ConfigValidationTests(unittest.TestCase):
    def test_local_dry_run_accepts_with_explicit_escape_hatch(self):
        validate_startup_config(
            SmtpProxyConfig(
                host="127.0.0.1",
                dry_run=True,
                require_auth=False,
                allow_unsafe_local_dry_run=True,
            )
        )

    def test_local_dry_run_rejects_without_explicit_escape_hatch(self):
        with self.assertRaisesRegex(
            StartupConfigError,
            "SMTP_PROXY_ALLOW_UNSAFE_LOCAL_DRY_RUN",
        ):
            validate_startup_config(
                SmtpProxyConfig(
                    host="127.0.0.1",
                    dry_run=True,
                    require_auth=False,
                )
            )

    def test_local_escape_hatch_requires_dry_run(self):
        with self.assertRaisesRegex(StartupConfigError, "SMTP_PROXY_DRY_RUN"):
            validate_startup_config(
                SmtpProxyConfig(
                    host="127.0.0.1",
                    dry_run=False,
                    allow_unsafe_local_dry_run=True,
                )
            )

    def test_remote_capable_bind_accepts_safe_config(self):
        validate_startup_config(safe_remote_config())

    def test_remote_capable_bind_rejects_escape_hatch(self):
        with self.assertRaisesRegex(
            StartupConfigError,
            "SMTP_PROXY_ALLOW_UNSAFE_LOCAL_DRY_RUN",
        ):
            validate_startup_config(
                safe_remote_config(allow_unsafe_local_dry_run=True)
            )

    def test_remote_capable_bind_rejects_auth_disabled(self):
        with self.assertRaisesRegex(StartupConfigError, "SMTP_PROXY_REQUIRE_AUTH"):
            validate_startup_config(safe_remote_config(require_auth=False))

    def test_remote_capable_bind_rejects_tls_disabled(self):
        with self.assertRaisesRegex(StartupConfigError, "SMTP_PROXY_REQUIRE_TLS"):
            validate_startup_config(safe_remote_config(require_tls=False))

    def test_remote_capable_bind_rejects_default_username(self):
        with self.assertRaisesRegex(StartupConfigError, "SMTP_PROXY_USERNAME"):
            validate_startup_config(safe_remote_config(username="user"))

    def test_remote_capable_bind_rejects_default_password_without_leaking_it(self):
        with self.assertRaises(StartupConfigError) as raised:
            validate_startup_config(safe_remote_config(password="change-me"))

        message = str(raised.exception)
        self.assertIn("SMTP_PROXY_PASSWORD", message)
        self.assertNotIn("change-me", message)

    def test_remote_capable_bind_rejects_empty_user_mailboxes(self):
        with self.assertRaisesRegex(StartupConfigError, "USER_MAILBOXES"):
            validate_startup_config(safe_remote_config(user_mailboxes=set()))

    def test_remote_capable_bind_rejects_direct_external_send(self):
        with self.assertRaisesRegex(StartupConfigError, "ALLOW_DIRECT_EXTERNAL_SEND"):
            validate_startup_config(
                safe_remote_config(allow_direct_external_send=True)
            )

    def test_bind_classification(self):
        for host in ("127.0.0.1", "localhost", "::1"):
            self.assertTrue(is_local_development_bind(host))

        for host in ("0.0.0.0", "::", "192.168.1.10", "smtp.example.com"):
            self.assertFalse(is_local_development_bind(host))

    def test_env_loads_local_dry_run_escape_hatch(self):
        with mock.patch.dict(
            os.environ,
            {"SMTP_PROXY_ALLOW_UNSAFE_LOCAL_DRY_RUN": "true"},
            clear=True,
        ):
            config = load_config_from_env()

        self.assertTrue(config.allow_unsafe_local_dry_run)


if __name__ == "__main__":
    unittest.main()
