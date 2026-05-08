import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from contacts_core import generated_contact_display_name


class NamingTests(unittest.TestCase):
    def test_generated_contact_display_name(self):
        self.assertEqual(
            generated_contact_display_name("Alice Example", "shopping@example.com"),
            "SL · Alice Example · shopping@example.com",
        )


if __name__ == "__main__":
    unittest.main()
