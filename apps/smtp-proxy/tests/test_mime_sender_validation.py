import os
import sys
import unittest
from email.message import EmailMessage

APP_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
CORE_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "alias-routing-core", "src")
sys.path.insert(0, os.path.abspath(APP_SRC))
sys.path.insert(0, os.path.abspath(CORE_SRC))

from sl_smtp_proxy.config import SmtpProxyConfig
from sl_smtp_proxy.mime_sender_validation import validate_mime_sender


class MimeSenderValidationTests(unittest.TestCase):
    def test_accepts_from_in_user_mailboxes(self):
        msg = EmailMessage()
        msg["From"] = "Allowed Sender <ALLOWED@example.com>"

        result = validate_mime_sender(
            msg,
            SmtpProxyConfig(user_mailboxes={"allowed@example.com"}),
        )

        self.assertTrue(result.accepted)
        self.assertEqual(result.from_count, 1)

    def test_accepts_all_from_addresses_in_user_mailboxes(self):
        msg = EmailMessage()
        msg["From"] = "Allowed <allowed@example.com>, Other <other@example.com>"

        result = validate_mime_sender(
            msg,
            SmtpProxyConfig(user_mailboxes={"allowed@example.com", "other@example.com"}),
        )

        self.assertTrue(result.accepted)
        self.assertEqual(result.from_count, 2)

    def test_rejects_missing_from_when_user_mailboxes_are_configured(self):
        result = validate_mime_sender(
            EmailMessage(),
            SmtpProxyConfig(user_mailboxes={"allowed@example.com"}),
        )

        self.assertFalse(result.accepted)
        self.assertEqual(result.header, "from")
        self.assertEqual(result.reason, "from_missing")

    def test_rejects_invalid_from_when_user_mailboxes_are_configured(self):
        msg = EmailMessage()
        msg["From"] = "not-an-email"

        result = validate_mime_sender(
            msg,
            SmtpProxyConfig(user_mailboxes={"allowed@example.com"}),
        )

        self.assertFalse(result.accepted)
        self.assertEqual(result.header, "from")
        self.assertEqual(result.reason, "from_invalid")

    def test_rejects_from_outside_user_mailboxes(self):
        msg = EmailMessage()
        msg["From"] = "intruder@example.com"

        result = validate_mime_sender(
            msg,
            SmtpProxyConfig(user_mailboxes={"allowed@example.com"}),
        )

        self.assertFalse(result.accepted)
        self.assertEqual(result.header, "from")
        self.assertEqual(result.reason, "from_not_allowed")

    def test_accepts_sender_in_user_mailboxes(self):
        msg = EmailMessage()
        msg["From"] = "allowed@example.com"
        msg["Sender"] = "other@example.com"

        result = validate_mime_sender(
            msg,
            SmtpProxyConfig(user_mailboxes={"allowed@example.com", "other@example.com"}),
        )

        self.assertTrue(result.accepted)
        self.assertEqual(result.sender_count, 1)

    def test_rejects_sender_outside_user_mailboxes(self):
        msg = EmailMessage()
        msg["From"] = "allowed@example.com"
        msg["Sender"] = "intruder@example.com"

        result = validate_mime_sender(
            msg,
            SmtpProxyConfig(user_mailboxes={"allowed@example.com"}),
        )

        self.assertFalse(result.accepted)
        self.assertEqual(result.header, "sender")
        self.assertEqual(result.reason, "sender_not_allowed")

    def test_rejects_invalid_sender_when_user_mailboxes_are_configured(self):
        msg = EmailMessage()
        msg["From"] = "allowed@example.com"
        msg["Sender"] = "not-an-email"

        result = validate_mime_sender(
            msg,
            SmtpProxyConfig(user_mailboxes={"allowed@example.com"}),
        )

        self.assertFalse(result.accepted)
        self.assertEqual(result.header, "sender")
        self.assertEqual(result.reason, "sender_invalid")

    def test_skips_validation_when_user_mailboxes_are_not_configured(self):
        msg = EmailMessage()
        msg["From"] = "not-an-email"
        msg["Sender"] = "intruder@example.com"

        result = validate_mime_sender(msg, SmtpProxyConfig(user_mailboxes=set()))

        self.assertTrue(result.accepted)


if __name__ == "__main__":
    unittest.main()
