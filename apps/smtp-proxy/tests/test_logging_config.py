import logging
import os
import sys
import unittest

APP_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
CORE_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "alias-routing-core", "src")
sys.path.insert(0, os.path.abspath(APP_SRC))
sys.path.insert(0, os.path.abspath(CORE_SRC))

from sl_smtp_proxy.logging import configure_logging


class ConfigureLoggingTests(unittest.TestCase):
    def tearDown(self):
        # configure_logging() calls logging.basicConfig(), which only ever
        # takes effect once per process and otherwise permanently raises
        # the root logger's level for the rest of the test run. Resetting
        # mail.log back to NOTSET here would make it inherit that
        # elevated root level in later tests and leak raw addresses the
        # same way production would without this module's fix. Restore
        # the safe default explicitly instead of trying to restore
        # whatever the (meaningless, pre-basicConfig) prior state was.
        logging.getLogger("mail.log").setLevel(logging.WARNING)

    def test_aiosmtpd_protocol_logger_defaults_to_warning(self):
        # aiosmtpd logs raw, unredacted MAIL FROM/RCPT TO lines under the
        # "mail.log" logger at INFO. Left alone, that bypasses this
        # application's own address redaction entirely.
        configure_logging("INFO")

        self.assertEqual(logging.getLogger("mail.log").getEffectiveLevel(), logging.WARNING)
        self.assertFalse(logging.getLogger("mail.log").isEnabledFor(logging.INFO))

    def test_aiosmtpd_protocol_log_level_is_configurable(self):
        configure_logging("INFO", aiosmtpd_log_level="DEBUG")

        self.assertTrue(logging.getLogger("mail.log").isEnabledFor(logging.DEBUG))

    def test_invalid_aiosmtpd_log_level_falls_back_to_warning(self):
        configure_logging("INFO", aiosmtpd_log_level="not-a-level")

        self.assertEqual(logging.getLogger("mail.log").getEffectiveLevel(), logging.WARNING)


if __name__ == "__main__":
    unittest.main()
