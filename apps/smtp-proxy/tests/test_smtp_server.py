import asyncio
import base64
from email import policy
from email.parser import BytesParser
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest
import warnings
from email.message import EmailMessage

from aiosmtpd.controller import Controller

APP_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
CORE_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "alias-routing-core", "src")
SIMPLELOGIN_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "simplelogin-client", "src")
sys.path.insert(0, os.path.abspath(APP_SRC))
sys.path.insert(0, os.path.abspath(CORE_SRC))
sys.path.insert(0, os.path.abspath(SIMPLELOGIN_SRC))

from sl_smtp_proxy.config import SmtpProxyConfig
from sl_smtp_proxy.healthcheck import check_health
from sl_smtp_proxy.smtp_server import SmtpProxyServer
from alias_routing_core import TransformAction


warnings.filterwarnings(
    "ignore",
    message="Requiring AUTH while not requiring TLS can lead to security vulnerabilities!",
    category=UserWarning,
)
warnings.filterwarnings(
    "ignore",
    message="Session.login_data is deprecated and will be removed in version 2.0",
)


def read_smtp_response(fileobj):
    lines = []
    while True:
        line = fileobj.readline().decode("utf-8", errors="replace").rstrip("\r\n")
        lines.append(line)
        if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
            return int(line[:3]), "\n".join(lines)


def send_smtp_line(fileobj, line):
    fileobj.write((line + "\r\n").encode("utf-8"))
    fileobj.flush()


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def make_test_cert(test_case):
    openssl = shutil.which("openssl")
    if not openssl:
        test_case.skipTest("openssl is required for TLS tests")

    tempdir = tempfile.TemporaryDirectory()
    test_case.addCleanup(tempdir.cleanup)
    cert_file = os.path.join(tempdir.name, "cert.pem")
    key_file = os.path.join(tempdir.name, "key.pem")
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key_file,
            "-out",
            cert_file,
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return cert_file, key_file


def insecure_client_tls_context():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def submit_message(port, msg, rcpt_tos, mail_from="sender@example.com"):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
        fileobj = sock.makefile("rwb", buffering=0)
        read_smtp_response(fileobj)
        send_smtp_line(fileobj, "EHLO test.local")
        read_smtp_response(fileobj)
        send_smtp_line(fileobj, f"MAIL FROM:<{mail_from}>")
        read_smtp_response(fileobj)
        for rcpt_to in rcpt_tos:
            send_smtp_line(fileobj, f"RCPT TO:<{rcpt_to}>")
            read_smtp_response(fileobj)
        send_smtp_line(fileobj, "DATA")
        read_smtp_response(fileobj)
        fileobj.write(msg.as_bytes().replace(b"\n", b"\r\n") + b"\r\n.\r\n")
        fileobj.flush()
        return read_smtp_response(fileobj)


def mail_from_response(port, mail_from="sender@example.com"):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
        fileobj = sock.makefile("rwb", buffering=0)
        read_smtp_response(fileobj)
        send_smtp_line(fileobj, "EHLO test.local")
        read_smtp_response(fileobj)
        send_smtp_line(fileobj, f"MAIL FROM:<{mail_from}>")
        return read_smtp_response(fileobj)


class CaptureUpstreamHandler:
    def __init__(self):
        self.messages = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append({
            "mail_from": envelope.mail_from,
            "rcpt_tos": list(envelope.rcpt_tos),
            "content": envelope.original_content,
        })
        return "250 OK"


class FakeResolverWithOwnedAliases:
    def __init__(self):
        self.calls = []

    def owned_alias_emails(self):
        return {"shopping@example.com"}

    def __call__(self, recipient, alias):
        self.calls.append((recipient, alias))
        return "reply+alice@simplelogin.co"


class SmtpServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = SmtpProxyServer(SmtpProxyConfig(host="127.0.0.1", port=0, require_auth=False))
        await self.server.start()

    async def asyncTearDown(self):
        await self.server.stop()

    async def test_smtp_client_submission_is_rejected_safely_after_planning(self):
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "alice@example.com"
        msg["Subject"] = "Private subject"
        msg.set_content("private body")

        def send_message():
            return submit_message(self.server.port, msg, ["alice@example.com"])

        result = await asyncio.get_running_loop().run_in_executor(None, send_message)

        self.assertEqual(result[0], 550)
        self.assertIn("SimpleLogin alias selection required", result[1])
        self.assertTrue(self.server.last_plan.rejected)

    async def test_healthcheck_passes_for_running_server(self):
        check_health(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=self.server.port,
                require_auth=False,
            ),
            timeout_seconds=2,
        )

    async def test_mail_from_rejects_sender_outside_user_mailboxes(self):
        sender_server = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                user_mailboxes={"allowed@example.com"},
            )
        )
        await sender_server.start()
        try:
            result = await asyncio.get_running_loop().run_in_executor(
                None,
                mail_from_response,
                sender_server.port,
                "intruder@example.com",
            )

            self.assertEqual(result[0], 550)
            self.assertIn("Sender address is not allowed", result[1])
        finally:
            await sender_server.stop()

    async def test_mail_from_accepts_configured_user_mailbox(self):
        sender_server = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                user_mailboxes={"allowed@example.com"},
            )
        )
        await sender_server.start()
        try:
            result = await asyncio.get_running_loop().run_in_executor(
                None,
                mail_from_response,
                sender_server.port,
                "ALLOWED@example.com",
            )

            self.assertEqual(result[0], 250)
        finally:
            await sender_server.stop()

    async def test_smtp_submission_uses_injected_resolver_for_rewrite_plan(self):
        rewrite_server = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=False,
            ),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
        )
        await rewrite_server.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("private body")

            def send_message():
                return submit_message(rewrite_server.port, msg, ["alice@example.com"])

            result = await asyncio.get_running_loop().run_in_executor(None, send_message)

            self.assertEqual(result[0], 550)
            self.assertIn("dry-run", result[1])
            self.assertFalse(rewrite_server.last_plan.rejected)
            self.assertEqual(rewrite_server.last_plan.actions[0].action, TransformAction.REWRITE)
            self.assertEqual(
                rewrite_server.last_plan.actions[0].replacement,
                "reply+alice@simplelogin.co",
            )
        finally:
            await rewrite_server.stop()

    async def test_cc_alias_selects_alias_for_reply_all_with_new_external_recipient(self):
        selected_aliases = []
        rewrite_server = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                alias_suffix_domains={"@example.net"},
                known_reverse_aliases={"reply+existing@simplelogin.co"},
            ),
            reverse_alias_resolver=lambda recipient, alias: (
                selected_aliases.append(alias) or "reply+alice@simplelogin.co"
            ),
        )
        await rewrite_server.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "reply+existing@simplelogin.co"
            msg["Cc"] = "newalias@example.net, alice@example.com"
            msg.set_content("private body")

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                rewrite_server.port,
                msg,
                ["reply+existing@simplelogin.co", "newalias@example.net", "alice@example.com"],
            )

            self.assertEqual(result[0], 550)
            self.assertIn("dry-run", result[1])
            self.assertEqual(selected_aliases, ["newalias@example.net"])
            self.assertFalse(rewrite_server.last_plan.rejected)
            self.assertEqual(rewrite_server.last_plan.selected_alias, "newalias@example.net")
            self.assertEqual(rewrite_server.last_plan.actions[0].action, TransformAction.KEEP)
            self.assertEqual(rewrite_server.last_plan.actions[1].action, TransformAction.DROP)
            self.assertEqual(rewrite_server.last_plan.actions[2].action, TransformAction.REWRITE)
        finally:
            await rewrite_server.stop()

    async def test_multiple_distinct_aliases_reject_at_smtp_layer(self):
        selected_aliases = []
        rewrite_server = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                alias_suffix_domains={"@example.net"},
            ),
            reverse_alias_resolver=lambda recipient, alias: (
                selected_aliases.append(alias) or "reply+alice@simplelogin.co"
            ),
        )
        await rewrite_server.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["Cc"] = "alias-one@example.net"
            msg["Bcc"] = "alias-two@example.net"
            msg.set_content("private body")

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                rewrite_server.port,
                msg,
                ["alice@example.com", "alias-one@example.net", "alias-two@example.net"],
            )

            self.assertEqual(result[0], 550)
            self.assertIn("Multiple distinct SimpleLogin aliases specified", result[1])
            self.assertEqual(selected_aliases, [])
            self.assertTrue(rewrite_server.last_plan.rejected)
        finally:
            await rewrite_server.stop()

    async def test_alias_suffix_bcc_selects_alias_without_control_domain(self):
        selected_aliases = []
        rewrite_server = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                alias_suffix_domains={"@example.net", ".suffix@sl.test"},
            ),
            reverse_alias_resolver=lambda recipient, alias: (
                selected_aliases.append(alias) or "reply+alice@simplelogin.co"
            ),
        )
        await rewrite_server.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["Bcc"] = "newalias@example.net"
            msg.set_content("private body")

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                rewrite_server.port,
                msg,
                ["alice@example.com", "newalias@example.net"],
            )

            self.assertEqual(result[0], 550)
            self.assertIn("dry-run", result[1])
            self.assertEqual(selected_aliases, ["newalias@example.net"])
            self.assertFalse(rewrite_server.last_plan.rejected)
            self.assertEqual(rewrite_server.last_plan.actions[0].action, TransformAction.REWRITE)
            self.assertEqual(rewrite_server.last_plan.actions[1].action, TransformAction.DROP)
        finally:
            await rewrite_server.stop()

    async def test_duplicate_cc_and_bcc_alias_selects_alias(self):
        selected_aliases = []
        rewrite_server = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                alias_suffix_domains={"@example.net"},
            ),
            reverse_alias_resolver=lambda recipient, alias: (
                selected_aliases.append(alias) or f"reverse-for-{recipient}"
            ),
        )
        await rewrite_server.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "recipient-one@example.org, recipient-two@example.org, reply+existing@simplelogin.co"
            msg["Cc"] = "alias@example.net"
            msg["Bcc"] = "alias@example.net"
            msg.set_content("hello")

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                rewrite_server.port,
                msg,
                [
                    "recipient-one@example.org",
                    "recipient-two@example.org",
                    "reply+existing@simplelogin.co",
                    "alias@example.net",
                    "alias@example.net",
                ],
                "sender@example.com",
            )

            self.assertEqual(result[0], 550)
            self.assertIn("dry-run", result[1])
            self.assertEqual(
                selected_aliases,
                ["alias@example.net", "alias@example.net"],
            )
            self.assertFalse(rewrite_server.last_plan.rejected)
            self.assertEqual(rewrite_server.last_plan.selected_alias, "alias@example.net")
        finally:
            await rewrite_server.stop()

    async def test_forwarding_rewrites_envelope_and_headers_before_upstream(self):
        upstream_handler = CaptureUpstreamHandler()
        upstream_port = free_port()
        upstream = Controller(
            upstream_handler,
            hostname="127.0.0.1",
            port=upstream_port,
            decode_data=False,
            ready_timeout=5.0,
        )
        upstream.start()
        proxy = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                dry_run=False,
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                alias_suffix_domains={"@example.net"},
                known_reverse_aliases={"reply+bob@simplelogin.co"},
            ),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "Alice <alice@example.com>"
            msg["Cc"] = "reply+bob@simplelogin.co"
            msg["Bcc"] = "orders@example.net"
            msg["X-SimpleLogin-Alias"] = "orders@example.net"
            msg.set_content("private body")

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                proxy.port,
                msg,
                [
                    "alice@example.com",
                    "reply+bob@simplelogin.co",
                    "orders@example.net",
                ],
            )

            self.assertEqual(result[0], 250)
            self.assertEqual(len(upstream_handler.messages), 1)
            captured = upstream_handler.messages[0]
            self.assertEqual(captured["mail_from"], "sender@example.com")
            self.assertEqual(
                captured["rcpt_tos"],
                ["reply+alice@simplelogin.co", "reply+bob@simplelogin.co"],
            )
            forwarded = BytesParser(policy=policy.default).parsebytes(captured["content"])
            self.assertEqual(forwarded.get("To"), "Alice <reply+alice@simplelogin.co>")
            self.assertEqual(forwarded.get("Cc"), "reply+bob@simplelogin.co")
            self.assertIsNone(forwarded.get("Bcc"))
            self.assertIsNone(forwarded.get("X-SimpleLogin-Alias"))
            self.assertIn("private body", forwarded.get_content())
            content = captured["content"].decode("utf-8", errors="replace")
            self.assertNotIn("alice@example.com", content)
            self.assertNotIn("orders@example.net", content)
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)


    async def test_forwarding_preserves_to_cover_alias_and_rewrites_bcc_recipients(self):
        upstream_handler = CaptureUpstreamHandler()
        upstream_port = free_port()
        upstream = Controller(
            upstream_handler,
            hostname="127.0.0.1",
            port=upstream_port,
            decode_data=False,
            ready_timeout=5.0,
        )
        upstream.start()
        proxy = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                dry_run=False,
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                alias_suffix_domains={"@example.net"},
            ),
            reverse_alias_resolver=lambda recipient, alias: f"reply+{recipient.split('@', 1)[0]}@simplelogin.co",
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "Announcements <announcements@example.net>"
            msg.set_content("private body")

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                proxy.port,
                msg,
                [
                    "announcements@example.net",
                    "alice@example.org",
                    "bob@example.org",
                ],
            )

            self.assertEqual(result[0], 250)
            captured = upstream_handler.messages[0]
            self.assertEqual(captured["rcpt_tos"], [
                "reply+alice@simplelogin.co",
                "reply+bob@simplelogin.co",
            ])
            forwarded = BytesParser(policy=policy.default).parsebytes(captured["content"])
            self.assertEqual(forwarded.get("To"), "Announcements <announcements@example.net>")
            self.assertIsNone(forwarded.get("Bcc"))
            self.assertEqual(proxy.last_plan.selected_alias, "announcements@example.net")
            self.assertEqual(proxy.last_plan.selected_alias_source, "cover_recipient")
            content = captured["content"].decode("utf-8", errors="replace")
            self.assertNotIn("alice@example.org", content)
            self.assertNotIn("bob@example.org", content)
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_forwarding_strips_api_discovered_own_alias_without_env_list(self):
        upstream_handler = CaptureUpstreamHandler()
        upstream_port = free_port()
        upstream = Controller(
            upstream_handler,
            hostname="127.0.0.1",
            port=upstream_port,
            decode_data=False,
            ready_timeout=5.0,
        )
        upstream.start()
        proxy = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                dry_run=False,
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                manual_simplelogin_aliases=set(),
                known_reverse_aliases={"reply+bob@simplelogin.co"},
            ),
            reverse_alias_resolver=FakeResolverWithOwnedAliases(),
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "reply+bob@simplelogin.co"
            msg["Cc"] = "shopping@example.com"
            msg.set_content("private body")

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                proxy.port,
                msg,
                ["reply+bob@simplelogin.co", "shopping@example.com"],
            )

            self.assertEqual(result[0], 250)
            captured = upstream_handler.messages[0]
            self.assertEqual(captured["rcpt_tos"], ["reply+bob@simplelogin.co"])
            forwarded = BytesParser(policy=policy.default).parsebytes(captured["content"])
            self.assertEqual(forwarded.get("To"), "reply+bob@simplelogin.co")
            self.assertIsNone(forwarded.get("Cc"))
            self.assertNotIn(
                "shopping@example.com",
                captured["content"].decode("utf-8", errors="replace"),
            )
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_upstream_unavailable_rejects_without_accepting_message(self):
        proxy = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                dry_run=False,
                upstream_host="127.0.0.1",
                upstream_port=free_port(),
            ),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("private body")

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                proxy.port,
                msg,
                ["alice@example.com"],
            )

            self.assertEqual(result[0], 550)
            self.assertIn("Upstream SMTP unavailable", result[1])
        finally:
            await proxy.stop()

    async def test_auth_required_rejects_unauthenticated_mail_from(self):
        auth_server = SmtpProxyServer(
            SmtpProxyConfig(host="127.0.0.1", port=0, require_auth=True, username="user", password="pass")
        )
        await auth_server.start()
        try:
            def send_message():
                with socket.create_connection(("127.0.0.1", auth_server.port), timeout=2) as sock:
                    fileobj = sock.makefile("rwb", buffering=0)
                    read_smtp_response(fileobj)
                    send_smtp_line(fileobj, "EHLO test.local")
                    read_smtp_response(fileobj)
                    send_smtp_line(fileobj, "MAIL FROM:<sender@example.com>")
                    return read_smtp_response(fileobj)

            result = await asyncio.get_running_loop().run_in_executor(None, send_message)

            self.assertEqual(result[0], 530)
            self.assertIn("Authentication required", result[1])
        finally:
            await auth_server.stop()

    async def test_auth_plain_accepts_configured_credentials(self):
        auth_server = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=True,
                username="user",
                password="pass",
            )
        )
        await auth_server.start()
        try:
            def authenticate():
                payload = base64.b64encode(b"\x00user\x00pass").decode("ascii")
                with socket.create_connection(("127.0.0.1", auth_server.port), timeout=2) as sock:
                    fileobj = sock.makefile("rwb", buffering=0)
                    read_smtp_response(fileobj)
                    send_smtp_line(fileobj, "EHLO test.local")
                    read_smtp_response(fileobj)
                    send_smtp_line(fileobj, f"AUTH PLAIN {payload}")
                    return read_smtp_response(fileobj)

            result = await asyncio.get_running_loop().run_in_executor(None, authenticate)

            self.assertEqual(result[0], 235)
        finally:
            await auth_server.stop()

    async def test_auth_login_accepts_configured_credentials(self):
        auth_server = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=True,
                username="user",
                password="pass",
            )
        )
        await auth_server.start()
        try:
            def authenticate():
                with socket.create_connection(("127.0.0.1", auth_server.port), timeout=2) as sock:
                    fileobj = sock.makefile("rwb", buffering=0)
                    read_smtp_response(fileobj)
                    send_smtp_line(fileobj, "EHLO test.local")
                    read_smtp_response(fileobj)
                    send_smtp_line(fileobj, "AUTH LOGIN")
                    self.assertEqual(read_smtp_response(fileobj)[0], 334)
                    send_smtp_line(fileobj, base64.b64encode(b"user").decode("ascii"))
                    self.assertEqual(read_smtp_response(fileobj)[0], 334)
                    send_smtp_line(fileobj, base64.b64encode(b"pass").decode("ascii"))
                    return read_smtp_response(fileobj)

            result = await asyncio.get_running_loop().run_in_executor(None, authenticate)

            self.assertEqual(result[0], 235)
        finally:
            await auth_server.stop()

    async def test_auth_login_can_be_disabled(self):
        auth_server = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=True,
                username="user",
                password="pass",
                auth_login_enabled=False,
            )
        )
        await auth_server.start()
        try:
            def authenticate():
                with socket.create_connection(("127.0.0.1", auth_server.port), timeout=2) as sock:
                    fileobj = sock.makefile("rwb", buffering=0)
                    read_smtp_response(fileobj)
                    send_smtp_line(fileobj, "EHLO test.local")
                    _, ehlo = read_smtp_response(fileobj)
                    send_smtp_line(fileobj, "AUTH LOGIN")
                    return ehlo, read_smtp_response(fileobj)

            ehlo, result = await asyncio.get_running_loop().run_in_executor(None, authenticate)

            self.assertIn("AUTH PLAIN", ehlo)
            self.assertNotIn("LOGIN", ehlo)
            self.assertEqual(result[0], 504)
        finally:
            await auth_server.stop()

    async def test_starttls_requires_tls_before_auth_and_accepts_login_after_upgrade(self):
        cert_file, key_file = make_test_cert(self)
        auth_server = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=True,
                require_tls=True,
                tls_mode="starttls",
                tls_cert_file=cert_file,
                tls_key_file=key_file,
                username="user",
                password="pass",
            )
        )
        await auth_server.start()
        try:
            def authenticate():
                sock = socket.create_connection(("127.0.0.1", auth_server.port), timeout=2)
                try:
                    fileobj = sock.makefile("rwb", buffering=0)
                    read_smtp_response(fileobj)
                    send_smtp_line(fileobj, "EHLO test.local")
                    _, plain_ehlo = read_smtp_response(fileobj)
                    self.assertIn("STARTTLS", plain_ehlo)
                    self.assertNotIn("AUTH", plain_ehlo)

                    send_smtp_line(fileobj, "AUTH LOGIN")
                    self.assertIn(read_smtp_response(fileobj)[0], {530, 538})

                    send_smtp_line(fileobj, "STARTTLS")
                    self.assertEqual(read_smtp_response(fileobj)[0], 220)
                    sock = insecure_client_tls_context().wrap_socket(
                        sock,
                        server_hostname="127.0.0.1",
                    )
                    fileobj = sock.makefile("rwb", buffering=0)
                    send_smtp_line(fileobj, "EHLO test.local")
                    _, tls_ehlo = read_smtp_response(fileobj)
                    self.assertIn("AUTH LOGIN PLAIN", tls_ehlo)

                    send_smtp_line(fileobj, "AUTH LOGIN")
                    self.assertEqual(read_smtp_response(fileobj)[0], 334)
                    send_smtp_line(fileobj, base64.b64encode(b"user").decode("ascii"))
                    self.assertEqual(read_smtp_response(fileobj)[0], 334)
                    send_smtp_line(fileobj, base64.b64encode(b"pass").decode("ascii"))
                    return read_smtp_response(fileobj)
                finally:
                    sock.close()

            result = await asyncio.get_running_loop().run_in_executor(None, authenticate)

            self.assertEqual(result[0], 235)
        finally:
            await auth_server.stop()

    async def test_implicit_tls_accepts_login_on_encrypted_socket(self):
        cert_file, key_file = make_test_cert(self)
        auth_server = SmtpProxyServer(
            SmtpProxyConfig(
                host="127.0.0.1",
                port=0,
                require_auth=True,
                require_tls=True,
                tls_mode="implicit",
                tls_cert_file=cert_file,
                tls_key_file=key_file,
                username="user",
                password="pass",
            )
        )
        await auth_server.start()
        try:
            def authenticate():
                raw_sock = socket.create_connection(("127.0.0.1", auth_server.port), timeout=2)
                with insecure_client_tls_context().wrap_socket(
                    raw_sock,
                    server_hostname="127.0.0.1",
                ) as sock:
                    fileobj = sock.makefile("rwb", buffering=0)
                    read_smtp_response(fileobj)
                    send_smtp_line(fileobj, "EHLO test.local")
                    _, ehlo = read_smtp_response(fileobj)
                    self.assertNotIn("STARTTLS", ehlo)
                    self.assertIn("AUTH LOGIN PLAIN", ehlo)
                    send_smtp_line(fileobj, "AUTH LOGIN")
                    self.assertEqual(read_smtp_response(fileobj)[0], 334)
                    send_smtp_line(fileobj, base64.b64encode(b"user").decode("ascii"))
                    self.assertEqual(read_smtp_response(fileobj)[0], 334)
                    send_smtp_line(fileobj, base64.b64encode(b"pass").decode("ascii"))
                    return read_smtp_response(fileobj)

            result = await asyncio.get_running_loop().run_in_executor(None, authenticate)

            self.assertEqual(result[0], 235)
        finally:
            await auth_server.stop()

    async def test_require_tls_refuses_start_until_tls_is_configured(self):
        tls_server = SmtpProxyServer(
            SmtpProxyConfig(host="127.0.0.1", port=0, require_auth=True, require_tls=True)
        )

        with self.assertRaisesRegex(RuntimeError, "SMTP_PROXY_TLS_CERT_FILE"):
            await tls_server.start()


if __name__ == "__main__":
    unittest.main()
