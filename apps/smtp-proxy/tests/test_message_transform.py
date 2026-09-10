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

from sl_smtp_proxy.config import SmtpProxyConfig
from alias_routing_core import (
    RecipientClassification,
    TransformAction,
    TransformPlan,
    TransformPlanItem,
)
from sl_smtp_proxy.message_transform import (
    apply_transform,
    build_plan_for_message,
    collect_alias_selector_recipients,
    transformed_envelope_recipients,
)


class MessageTransformTests(unittest.TestCase):
    def test_control_headers_are_removed_and_visible_headers_are_rewritten(self):
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "Alice <alice@example.com>"
        msg["Cc"] = "shopping@example.com, reply+bob@simplelogin.co"
        msg["Bcc"] = "shopping@example.com"
        msg["X-SimpleLogin-Alias"] = "shopping@example.com"
        msg["X-SimpleLogin-Contact-Lists"] = "Vendors"
        msg.set_content("hello body")

        cfg = SmtpProxyConfig(
            require_auth=False,
            manual_simplelogin_aliases={"shopping@example.com"},
            known_reverse_aliases={"reply+bob@simplelogin.co"},
        )
        _, plan = build_plan_for_message(
            "sender@example.com",
            ["alice@example.com", "shopping@example.com", "reply+bob@simplelogin.co"],
            msg.as_bytes(),
            cfg,
            reverse_alias_resolver=lambda original, alias: "reply+alice@simplelogin.co",
        )

        transformed = apply_transform(msg, plan, cfg)

        self.assertIsNone(transformed.get("X-SimpleLogin-Alias"))
        self.assertIsNone(transformed.get("X-SimpleLogin-Contact-Lists"))
        self.assertEqual(transformed.get("To"), "Alice <reply+alice@simplelogin.co>")
        self.assertEqual(transformed.get("Cc"), "reply+bob@simplelogin.co")
        self.assertIsNone(transformed.get("Bcc"))

    def test_duplicate_envelope_recipient_identifies_stripped_bcc_selector(self):
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "alice@example.com"
        msg["Cc"] = "alias@example.net"
        msg.set_content("hello body")

        selectors = collect_alias_selector_recipients(
            msg,
            [
                "alice@example.com",
                "alias@example.net",
                "alias@example.net",
            ],
        )

        self.assertEqual(selectors, ["alias@example.net"])



    def test_cc_alias_selects_alias_strips_cc_alias_and_rewrites_new_recipient(self):
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "reply+existing@simplelogin.co"
        msg["Cc"] = "Alias <alias@example.net>, Alice <alice@example.org>"
        msg.set_content("hello body")

        cfg = SmtpProxyConfig(
            require_auth=False,
            alias_suffix_domains={"@example.net"},
            known_reverse_aliases={"reply+existing@simplelogin.co"},
        )
        _, plan = build_plan_for_message(
            "sender@example.com",
            [
                "reply+existing@simplelogin.co",
                "alias@example.net",
                "alice@example.org",
            ],
            msg.as_bytes(),
            cfg,
            reverse_alias_resolver=lambda original, alias: "reply+alice@simplelogin.co",
        )

        transformed = apply_transform(msg, plan, cfg)

        self.assertFalse(plan.rejected)
        self.assertEqual(plan.selected_alias, "alias@example.net")
        self.assertEqual(plan.selected_alias_source, "recipient_alias")
        self.assertEqual(transformed.get("To"), "reply+existing@simplelogin.co")
        self.assertEqual(transformed.get("Cc"), "Alice <reply+alice@simplelogin.co>")
        self.assertEqual(transformed_envelope_recipients(plan), [
            "reply+existing@simplelogin.co",
            "reply+alice@simplelogin.co",
        ])

    def test_to_alias_with_bcc_recipients_selects_cover_alias_and_preserves_to_header(self):
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "Announcements <announcements@example.net>"
        msg.set_content("hello body")

        cfg = SmtpProxyConfig(
            require_auth=False,
            alias_suffix_domains={"@example.net"},
        )
        _, plan = build_plan_for_message(
            "sender@example.com",
            [
                "announcements@example.net",
                "alice@example.org",
                "bob@example.org",
            ],
            msg.as_bytes(),
            cfg,
            reverse_alias_resolver=lambda original, alias: f"reply+{original.split('@', 1)[0]}@simplelogin.co",
        )

        transformed = apply_transform(msg, plan, cfg)

        self.assertFalse(plan.rejected)
        self.assertEqual(plan.selected_alias, "announcements@example.net")
        self.assertEqual(plan.selected_alias_source, "cover_recipient")
        self.assertEqual([item.action for item in plan.actions], [
            TransformAction.DROP,
            TransformAction.REWRITE,
            TransformAction.REWRITE,
        ])
        self.assertEqual(transformed.get("To"), "Announcements <announcements@example.net>")
        self.assertIsNone(transformed.get("Bcc"))
        self.assertEqual(transformed_envelope_recipients(plan), [
            "reply+alice@simplelogin.co",
            "reply+bob@simplelogin.co",
        ])

    def test_duplicate_visible_alias_in_envelope_selects_alias_and_rewrites_external_recipients(self):
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient-one@example.org, recipient-two@example.org, reply+existing@simplelogin.co"
        msg["Cc"] = "alias@example.net"
        msg.set_content("hello body")

        cfg = SmtpProxyConfig(
            require_auth=False,
            alias_suffix_domains={"@example.net"},
        )
        _, plan = build_plan_for_message(
            "sender@example.com",
            [
                "recipient-one@example.org",
                "recipient-two@example.org",
                "reply+existing@simplelogin.co",
                "alias@example.net",
                "alias@example.net",
            ],
            msg.as_bytes(),
            cfg,
            reverse_alias_resolver=lambda original, alias: f"reverse-for-{original}",
        )

        self.assertFalse(plan.rejected)
        self.assertEqual(plan.selected_alias, "alias@example.net")
        self.assertEqual([item.action for item in plan.actions], [
            TransformAction.REWRITE,
            TransformAction.REWRITE,
            TransformAction.KEEP,
            TransformAction.DROP,
        ])


    def test_reverse_alias_and_new_recipient_in_same_to_header_are_both_handled(self):
        # Regression for the reported incident: a reply where an existing
        # reverse alias was moved into To alongside a newly added ordinary
        # recipient, with the sender's own alias left in Cc. The ordinary
        # recipient must be converted to a reverse alias, not forwarded
        # literally.
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "reply+existing@simplelogin.co, newperson@example.com"
        msg["Cc"] = "shopping@example.com"
        msg.set_content("private body")

        cfg = SmtpProxyConfig(
            require_auth=False,
            known_reverse_aliases={"reply+existing@simplelogin.co"},
        )
        _, plan = build_plan_for_message(
            "sender@example.com",
            [
                "reply+existing@simplelogin.co",
                "newperson@example.com",
                "shopping@example.com",
            ],
            msg.as_bytes(),
            cfg,
            reverse_alias_resolver=lambda original, alias: f"reply+{original.split('@', 1)[0]}@simplelogin.co",
            extra_simplelogin_aliases={"shopping@example.com"},
        )

        transformed = apply_transform(msg, plan, cfg)

        self.assertFalse(plan.rejected)
        self.assertEqual(transformed.get("To"), "reply+existing@simplelogin.co, reply+newperson@simplelogin.co")
        self.assertIsNone(transformed.get("Cc"))
        self.assertNotIn("newperson@example.com", transformed.as_string())
        self.assertEqual(transformed_envelope_recipients(plan), [
            "reply+existing@simplelogin.co",
            "reply+newperson@simplelogin.co",
        ])

    def test_rewrite_header_never_leaks_rejected_recipient_as_literal_text(self):
        # Regression: rewrite_address_header/_replacement_for must never
        # let a REJECTED recipient survive as literal text in a rewritten
        # header. Previously the DROP/REWRITE/KEEP if-chain had no branch
        # for REJECT, so it silently fell through and treated an
        # unresolved recipient as "not matched", passing it through
        # unchanged. This plan is deliberately not marked `rejected` to
        # exercise rewrite_address_header/apply_transform in isolation
        # (defense-in-depth, independent of the fail_closed gate).
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "reply+existing@simplelogin.co, unresolved@example.com"
        msg.set_content("private body")

        cfg = SmtpProxyConfig(require_auth=False)
        plan = TransformPlan(
            selected_alias="shopping@example.com",
            actions=[
                TransformPlanItem(
                    original="reply+existing@simplelogin.co",
                    classification=RecipientClassification.KNOWN_REVERSE_ALIAS,
                    action=TransformAction.KEEP,
                ),
                TransformPlanItem(
                    original="unresolved@example.com",
                    classification=RecipientClassification.EXTERNAL_RECIPIENT,
                    action=TransformAction.REJECT,
                    reason="reverse alias lookup failed: boom",
                ),
            ],
            rejected=False,
        )

        transformed = apply_transform(msg, plan, cfg)

        self.assertNotIn("unresolved@example.com", transformed.as_string())
        self.assertEqual(transformed.get("To"), "reply+existing@simplelogin.co")
        self.assertEqual(transformed_envelope_recipients(plan), ["reply+existing@simplelogin.co"])


if __name__ == "__main__":
    unittest.main()
