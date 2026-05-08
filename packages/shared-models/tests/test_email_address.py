import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from shared_models import normalize_email_address, parse_email_address


class EmailAddressTests(unittest.TestCase):
    def test_parse_and_normalize_display_address(self):
        self.assertEqual(parse_email_address("Alice <ALICE@example.COM>"), "ALICE@example.COM")
        self.assertEqual(normalize_email_address("Alice <ALICE@example.COM>"), "alice@example.com")


if __name__ == "__main__":
    unittest.main()
