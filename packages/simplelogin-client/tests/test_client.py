import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplelogin_client import AliasContact, SimpleLoginApiError, SimpleLoginClient


class FakeResponse:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self.payload = payload or {}
        self.text = text

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.headers = {}

    def request(self, method, url, params=None, json=None, timeout=None):
        self.requests.append({
            "method": method,
            "url": url,
            "params": params,
            "json": json,
            "timeout": timeout,
        })
        return self.responses.pop(0)


class SimpleLoginClientTests(unittest.TestCase):
    def test_list_aliases(self):
        session = FakeSession([
            FakeResponse(200, {"aliases": [{"id": 123, "email": "shopping@example.com"}]}),
        ])
        client = SimpleLoginClient("https://sl.test", "secret-token", session=session)

        aliases = client.list_aliases()

        self.assertEqual(len(aliases), 1)
        self.assertEqual(aliases[0].id, "123")
        self.assertEqual(aliases[0].email, "shopping@example.com")

    def test_list_contacts(self):
        session = FakeSession([
            FakeResponse(200, {"contacts": [{
                "id": 456,
                "contact": "Alice <alice@example.com>",
                "reverse_alias_address": "reply+alice@simplelogin.co",
            }]}),
        ])
        client = SimpleLoginClient("https://sl.test", "secret-token", session=session)

        contacts = client.list_contacts("123")

        self.assertEqual(contacts, [
            AliasContact(
                id="456",
                alias_id="123",
                contact="Alice <alice@example.com>",
                reverse_alias=None,
                reverse_alias_address="reply+alice@simplelogin.co",
            )
        ])

    def test_get_or_create_returns_existing_contact(self):
        session = FakeSession([
            FakeResponse(200, {"contacts": [{
                "id": 456,
                "contact": "Alice <alice@example.com>",
                "reverse_alias_address": "reply+alice@simplelogin.co",
            }]}),
        ])
        client = SimpleLoginClient("https://sl.test", "secret-token", session=session)

        contact = client.get_or_create_contact("123", "alice@example.com")

        self.assertEqual(contact.id, "456")
        self.assertEqual(len(session.requests), 1)

    def test_get_or_create_creates_missing_contact(self):
        session = FakeSession([
            FakeResponse(200, {"contacts": []}),
            FakeResponse(200, {
                "contact": {
                    "id": 789,
                    "contact": "Bob <bob@example.com>",
                    "reverse_alias_address": "reply+bob@simplelogin.co",
                }
            }),
        ])
        client = SimpleLoginClient("https://sl.test", "secret-token", session=session)

        contact = client.get_or_create_contact("123", "Bob <bob@example.com>")

        self.assertEqual(contact.id, "789")
        self.assertEqual(session.requests[1]["method"], "POST")
        self.assertEqual(session.requests[1]["json"], {"contact": "Bob <bob@example.com>"})

    def test_api_error_redacts_api_key(self):
        session = FakeSession([
            FakeResponse(500, text="failure secret-token"),
        ])
        client = SimpleLoginClient("https://sl.test", "secret-token", session=session)

        with self.assertRaises(SimpleLoginApiError) as raised:
            client.list_aliases()

        self.assertNotIn("secret-token", str(raised.exception))
        self.assertIn("[REDACTED]", str(raised.exception))

    def test_blocked_contact_flag_is_modeled(self):
        session = FakeSession([
            FakeResponse(200, {"contacts": [{
                "id": 456,
                "contact": "Alice <alice@example.com>",
                "reverse_alias_address": "reply+alice@simplelogin.co",
                "block_forward": True,
            }]}),
        ])
        client = SimpleLoginClient("https://sl.test", "secret-token", session=session)

        contact = client.list_contacts("123")[0]

        self.assertTrue(contact.block_forward)


if __name__ == "__main__":
    unittest.main()
