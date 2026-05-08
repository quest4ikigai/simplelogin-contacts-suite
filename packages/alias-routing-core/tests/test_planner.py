import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from alias_routing_core import (
    RecipientClassification,
    RoutingContext,
    TransformAction,
    build_transform_plan,
    select_simplelogin_alias,
)


def resolver(original, selected_alias):
    return f"reply+{original.split('@', 1)[0]}@simplelogin.co"


class PlannerTests(unittest.TestCase):
    def test_external_recipient_is_rewritten_with_header_alias(self):
        context = RoutingContext()

        plan = build_transform_plan(
            ["alice@example.com"],
            context,
            header_alias="shopping@example.com",
            reverse_alias_resolver=resolver,
        )

        self.assertFalse(plan.rejected)
        self.assertEqual(plan.actions[0].classification, RecipientClassification.EXTERNAL_RECIPIENT)
        self.assertEqual(plan.actions[0].action, TransformAction.REWRITE)
        self.assertEqual(plan.actions[0].replacement, "reply+alice@simplelogin.co")

    def test_reply_all_cleanup_drops_own_alias_and_keeps_reverse_aliases(self):
        context = RoutingContext(
            own_simplelogin_aliases={"shopping@example.com"},
            known_reverse_aliases={"reply+alice@simplelogin.co", "reply+bob@simplelogin.co"},
        )

        plan = build_transform_plan(
            [
                "reply+alice@simplelogin.co",
                "shopping@example.com",
                "reply+bob@simplelogin.co",
            ],
            context,
        )

        self.assertFalse(plan.rejected)
        self.assertEqual([item.action for item in plan.actions], [
            TransformAction.KEEP,
            TransformAction.DROP,
            TransformAction.KEEP,
        ])

    def test_alias_suffix_recipient_selects_alias_and_is_dropped(self):
        context = RoutingContext(alias_suffix_domains={"@example.net"})

        plan = build_transform_plan(
            ["newalias@example.net", "alice@example.com"],
            context,
            alias_selector_recipients=["newalias@example.net"],
            reverse_alias_resolver=resolver,
        )

        self.assertEqual(plan.selected_alias, "newalias@example.net")
        self.assertEqual(plan.actions[0].classification, RecipientClassification.OWN_SIMPLELOGIN_ALIAS)
        self.assertEqual(plan.actions[0].action, TransformAction.DROP)
        self.assertEqual(plan.actions[1].action, TransformAction.REWRITE)

    def test_premium_suffix_recipient_selects_alias_and_is_dropped(self):
        context = RoutingContext(alias_suffix_domains={".suffix@sl.test"})

        plan = build_transform_plan(
            ["randomalias.suffix@sl.test", "alice@example.com"],
            context,
            alias_selector_recipients=["randomalias.suffix@sl.test"],
            reverse_alias_resolver=resolver,
        )

        self.assertEqual(plan.selected_alias, "randomalias.suffix@sl.test")
        self.assertEqual(plan.actions[0].action, TransformAction.DROP)
        self.assertEqual(plan.actions[1].action, TransformAction.REWRITE)

    def test_header_alias_wins_over_alias_suffix_recipient(self):
        context = RoutingContext(
            alias_suffix_domains={"@example.net"},
        )

        alias = select_simplelogin_alias(
            ["newalias@example.net"],
            context,
            header_alias="header@example.com",
        )

        self.assertEqual(alias, "header@example.com")

    def test_alias_suffix_recipient_anywhere_selects_alias(self):
        context = RoutingContext(alias_suffix_domains={"@example.net"})

        plan = build_transform_plan(
            ["newalias@example.net", "alice@example.com"],
            context,
            reverse_alias_resolver=resolver,
        )

        self.assertFalse(plan.rejected)
        self.assertEqual(plan.selected_alias, "newalias@example.net")
        self.assertEqual(plan.selected_alias_source, "recipient_alias")
        self.assertEqual(plan.actions[0].action, TransformAction.DROP)
        self.assertEqual(plan.actions[1].action, TransformAction.REWRITE)


    def test_cover_recipient_selects_alias_and_rewrites_external_recipients(self):
        context = RoutingContext(alias_suffix_domains={"@example.net"})

        plan = build_transform_plan(
            ["announcements@example.net", "alice@example.org", "bob@example.org"],
            context,
            cover_recipient_candidates=["announcements@example.net"],
            reverse_alias_resolver=resolver,
        )

        self.assertFalse(plan.rejected)
        self.assertEqual(plan.selected_alias, "announcements@example.net")
        self.assertEqual(plan.selected_alias_source, "cover_recipient")
        self.assertEqual([item.action for item in plan.actions], [
            TransformAction.DROP,
            TransformAction.REWRITE,
            TransformAction.REWRITE,
        ])

    def test_known_owned_cover_recipient_selects_alias_without_suffix_match(self):
        context = RoutingContext(own_simplelogin_aliases={"announcements@example.com"})

        plan = build_transform_plan(
            ["announcements@example.com", "alice@example.org"],
            context,
            cover_recipient_candidates=["announcements@example.com"],
            reverse_alias_resolver=resolver,
        )

        self.assertFalse(plan.rejected)
        self.assertEqual(plan.selected_alias, "announcements@example.com")
        self.assertEqual(plan.selected_alias_source, "cover_recipient")
        self.assertEqual([item.action for item in plan.actions], [
            TransformAction.DROP,
            TransformAction.REWRITE,
        ])


    def test_multiple_distinct_aliases_reject(self):
        context = RoutingContext(alias_suffix_domains={"@example.net"})

        plan = build_transform_plan(
            ["cover@example.net", "selector@example.net", "alice@example.org"],
            context,
            alias_selector_recipients=["selector@example.net"],
            cover_recipient_candidates=["cover@example.net"],
            reverse_alias_resolver=resolver,
        )

        self.assertTrue(plan.rejected)
        self.assertIsNone(plan.selected_alias)
        self.assertEqual(plan.rejection_reason, "Multiple distinct SimpleLogin aliases specified")

    def test_duplicate_same_alias_is_allowed(self):
        context = RoutingContext(alias_suffix_domains={"@example.net"})

        plan = build_transform_plan(
            ["alias@example.net", "alias@example.net", "alice@example.org"],
            context,
            alias_selector_recipients=["alias@example.net"],
            reverse_alias_resolver=resolver,
        )

        self.assertFalse(plan.rejected)
        self.assertEqual(plan.selected_alias, "alias@example.net")
        self.assertEqual(plan.actions[2].action, TransformAction.REWRITE)

    def test_header_alias_conflicting_with_recipient_alias_rejects(self):
        context = RoutingContext(alias_suffix_domains={"@example.net"})

        plan = build_transform_plan(
            ["recipient@example.net", "alice@example.org"],
            context,
            header_alias="header@example.net",
            reverse_alias_resolver=resolver,
        )

        self.assertTrue(plan.rejected)
        self.assertEqual(plan.rejection_reason, "Multiple distinct SimpleLogin aliases specified")

    def test_external_recipient_rejects_without_alias(self):
        context = RoutingContext()

        plan = build_transform_plan(["alice@example.com"], context)

        self.assertTrue(plan.rejected)
        self.assertEqual(plan.actions[0].action, TransformAction.REJECT)
        self.assertEqual(plan.rejection_reason, "SimpleLogin alias selection required")

    def test_unknown_simplelogin_address_is_kept_with_warning(self):
        context = RoutingContext()

        plan = build_transform_plan(["reply+unknown@simplelogin.co"], context)

        self.assertFalse(plan.rejected)
        self.assertEqual(plan.actions[0].action, TransformAction.KEEP)
        self.assertTrue(plan.actions[0].warning)

    def test_all_reverse_alias_recipients_do_not_need_selected_alias(self):
        context = RoutingContext(
            known_reverse_aliases={"reply+alice@simplelogin.co", "reply+bob@simplelogin.co"},
        )

        plan = build_transform_plan(
            ["reply+alice@simplelogin.co", "reply+bob@simplelogin.co"],
            context,
        )

        self.assertFalse(plan.rejected)
        self.assertIsNone(plan.selected_alias)
        self.assertEqual([item.action for item in plan.actions], [TransformAction.KEEP, TransformAction.KEEP])


if __name__ == "__main__":
    unittest.main()
