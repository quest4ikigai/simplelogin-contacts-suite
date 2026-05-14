import os
import sys
import unittest
from email.message import EmailMessage

APP_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
CORE_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "alias-routing-core", "src")
SIMPLELOGIN_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "simplelogin-client", "src")
sys.path.insert(0, os.path.abspath(APP_SRC))
sys.path.insert(0, os.path.abspath(CORE_SRC))
sys.path.insert(0, os.path.abspath(SIMPLELOGIN_SRC))

from alias_routing_core import TransformPlan
from sl_smtp_proxy.config import SmtpProxyConfig
from sl_smtp_proxy.safety_verifier import verify_post_transform_safety


class SafetyVerifierTests(unittest.TestCase):
    def test_rejects_remaining_bcc_header(self):
        msg = self._message()
        msg["Bcc"] = "alias@example.net"

        result = verify_post_transform_safety(msg, ["reply+safe@simplelogin.co"], self._config(), self._plan())

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "bcc_header_present")

    def test_rejects_remaining_simplelogin_control_header(self):
        msg = self._message()
        msg["X-SimpleLogin-Alias"] = "alias@example.net"

        result = verify_post_transform_safety(msg, ["reply+safe@simplelogin.co"], self._config(), self._plan())

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "simplelogin_control_header_present")

    def test_rejects_direct_external_envelope_recipient(self):
        msg = self._message(to="reply+safe@simplelogin.co")

        result = verify_post_transform_safety(msg, ["alice@example.com"], self._config(), self._plan())

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "direct_external_envelope_recipient")

    def test_rejects_direct_external_visible_recipient(self):
        msg = self._message(to="Alice <alice@example.com>")

        result = verify_post_transform_safety(msg, ["reply+safe@simplelogin.co"], self._config(), self._plan())

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "direct_external_visible_recipient")

    def test_allows_direct_external_recipients_when_explicitly_enabled(self):
        msg = self._message(to="Alice <alice@example.com>")
        cfg = self._config(allow_direct_external_send=True)

        result = verify_post_transform_safety(msg, ["alice@example.com"], cfg, self._plan())

        self.assertTrue(result.accepted)

    def test_rejects_own_simplelogin_alias_in_envelope(self):
        msg = self._message(to="reply+safe@simplelogin.co")

        result = verify_post_transform_safety(msg, ["alias@example.net"], self._config(), self._plan())

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "own_simplelogin_alias_envelope_recipient")

    def test_rejects_own_mailbox_in_envelope(self):
        msg = self._message(to="reply+safe@simplelogin.co")

        result = verify_post_transform_safety(msg, ["sender@example.com"], self._config(), self._plan())

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "own_mailbox_envelope_recipient")

    def test_rejects_own_simplelogin_alias_in_visible_headers(self):
        msg = self._message(to="Alias <alias@example.net>")

        result = verify_post_transform_safety(msg, ["reply+safe@simplelogin.co"], self._config(), self._plan())

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "own_simplelogin_alias_visible_recipient")

    def test_rejects_own_mailbox_in_visible_headers(self):
        msg = self._message(to="Sender <sender@example.com>")

        result = verify_post_transform_safety(msg, ["reply+safe@simplelogin.co"], self._config(), self._plan())

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "own_mailbox_visible_recipient")

    def test_allows_single_preserved_cover_recipient_alias_in_to(self):
        msg = self._message(to="Announcements <alias@example.net>")

        result = verify_post_transform_safety(
            msg,
            ["reply+safe@simplelogin.co"],
            self._config(),
            self._plan(selected_alias_source="cover_recipient"),
        )

        self.assertTrue(result.accepted)

    def test_rejects_multiple_preserved_cover_recipient_aliases_in_to(self):
        msg = self._message(to="Announcements <alias@example.net>, Alias <alias@example.net>")

        result = verify_post_transform_safety(
            msg,
            ["reply+safe@simplelogin.co"],
            self._config(),
            self._plan(selected_alias_source="cover_recipient"),
        )

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "multiple_cover_recipient_aliases_visible")

    def _message(self, to="reply+safe@simplelogin.co"):
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = to
        msg.set_content("hello")
        return msg

    def _config(self, **overrides):
        values = {
            "require_auth": False,
            "alias_suffix_domains": {"@example.net"},
            "user_mailboxes": {"sender@example.com"},
        }
        values.update(overrides)
        return SmtpProxyConfig(**values)

    def _plan(self, selected_alias_source=None):
        return TransformPlan(
            selected_alias="alias@example.net",
            selected_alias_source=selected_alias_source,
            actions=[],
        )


if __name__ == "__main__":
    unittest.main()
