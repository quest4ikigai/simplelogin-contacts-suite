import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from alias_routing_core import RecipientClassification, RoutingContext, classify_address


class ClassifierTests(unittest.TestCase):
    def test_own_simplelogin_alias_is_classified_first(self):
        context = RoutingContext(own_simplelogin_aliases={"shopping@example.com"})

        classification, _ = classify_address("Shopping <shopping@example.com>", context)

        self.assertEqual(classification, RecipientClassification.OWN_SIMPLELOGIN_ALIAS)

    def test_own_mailbox_is_classified(self):
        context = RoutingContext(own_mailboxes={"sender@example.com"})

        classification, _ = classify_address("SENDER@example.com", context)

        self.assertEqual(classification, RecipientClassification.OWN_MAILBOX)

    def test_known_reverse_alias_is_kept_classification(self):
        context = RoutingContext(known_reverse_aliases={"reply+abc@simplelogin.co"})

        classification, _ = classify_address("reply+abc@simplelogin.co", context)

        self.assertEqual(classification, RecipientClassification.KNOWN_REVERSE_ALIAS)

    def test_unknown_simplelogin_address_is_probable_reverse_alias(self):
        context = RoutingContext()

        classification, _ = classify_address("reply+unknown@simplelogin.co", context)

        self.assertEqual(classification, RecipientClassification.PROBABLE_REVERSE_ALIAS)

    def test_external_recipient_is_classified(self):
        context = RoutingContext()

        classification, _ = classify_address("Alice <alice@example.com>", context)

        self.assertEqual(classification, RecipientClassification.EXTERNAL_RECIPIENT)

    def test_alias_suffix_domain_is_classified_as_own_alias(self):
        context = RoutingContext(alias_suffix_domains={"@example.net", ".suffix@sl.test"})

        classification, _ = classify_address("newalias@example.net", context)

        self.assertEqual(classification, RecipientClassification.OWN_SIMPLELOGIN_ALIAS)

    def test_public_suffix_domain_is_classified_as_own_alias(self):
        context = RoutingContext(alias_suffix_domains={".suffix@sl.test"})

        classification, _ = classify_address("randomalias.suffix@sl.test", context)

        self.assertEqual(classification, RecipientClassification.OWN_SIMPLELOGIN_ALIAS)

    def test_unlisted_alias_suffix_domain_is_external(self):
        context = RoutingContext(alias_suffix_domains={"@example.net"})

        classification, _ = classify_address("shopping@otherdomain.com", context)

        self.assertEqual(classification, RecipientClassification.EXTERNAL_RECIPIENT)


if __name__ == "__main__":
    unittest.main()
