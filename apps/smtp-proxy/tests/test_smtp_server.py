import asyncio
import base64
import json
import logging
from email import policy
from email.parser import BytesParser
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import warnings
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from aiosmtpd.controller import Controller

APP_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
CORE_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "alias-routing-core", "src")
SIMPLELOGIN_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "simplelogin-client", "src")
sys.path.insert(0, os.path.abspath(APP_SRC))
sys.path.insert(0, os.path.abspath(CORE_SRC))
sys.path.insert(0, os.path.abspath(SIMPLELOGIN_SRC))

from sl_smtp_proxy.config import SmtpProxyConfig, load_config_from_env
from sl_smtp_proxy.config_validation import StartupConfigError
from sl_smtp_proxy.forwarder import UpstreamSmtpForwarder
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


class FakeSimpleLoginHttpServer:
    def __init__(self, test_case):
        self.requests = []
        self.aliases = [{"id": 123, "email": "orders@example.net"}]
        self.contacts = []
        self.created_contact = {
            "id": 456,
            "contact": "Alice <alice@example.com>",
            "reverse_alias_address": "reply+alice@simplelogin.co",
        }
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                fake.requests.append((self.command, self.path, self.headers.get("Authentication"), None))
                if self.path == "/api/v2/aliases?page_id=0":
                    self._json(200, {"aliases": fake.aliases})
                    return
                if self.path == "/api/aliases/123/contacts?page_id=0":
                    self._json(200, {"contacts": fake.contacts})
                    return
                self._json(404, {"error": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                fake.requests.append((self.command, self.path, self.headers.get("Authentication"), body))
                if self.path == "/api/aliases/123/contacts":
                    self._json(201, {"contact": fake.created_contact})
                    return
                self._json(404, {"error": "not found"})

            def log_message(self, format, *args):
                return

            def _json(self, status, payload):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        test_case.addCleanup(self.close)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()
        self.thread.join(timeout=2)
        self.httpd.server_close()


class FakeResolverWithOwnedAliases:
    def __init__(self):
        self.calls = []

    def owned_alias_emails(self):
        return {"shopping@example.com"}

    def __call__(self, recipient, alias):
        self.calls.append((recipient, alias))
        return "reply+alice@simplelogin.co"


def local_smtp_config(**overrides):
    values = {"host": "127.0.0.1", "port": 0}
    values.update(overrides)
    if values.get("dry_run", True):
        values.setdefault("allow_unsafe_local_dry_run", True)
    return SmtpProxyConfig(**values)


class UpstreamForwarderTests(unittest.TestCase):
    def _message(self):
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg.set_content("hello")
        return msg

    def test_upstream_starttls_uses_verifying_context_before_auth(self):
        smtp = mock.MagicMock()
        smtp_cm = mock.MagicMock()
        smtp_cm.__enter__.return_value = smtp
        tls_context = object()

        with mock.patch("sl_smtp_proxy.forwarder.ssl.create_default_context", return_value=tls_context):
            with mock.patch("sl_smtp_proxy.forwarder.smtplib.SMTP", return_value=smtp_cm) as smtp_cls:
                UpstreamSmtpForwarder(
                    SmtpProxyConfig(
                        upstream_tls_mode="starttls",
                        upstream_username="user",
                        upstream_password="pass",
                    )
                ).forward("sender@example.com", ["recipient@example.com"], self._message())

        smtp_cls.assert_called_once_with("host.docker.internal", 1025, timeout=30)
        smtp.starttls.assert_called_once_with(context=tls_context)
        smtp.login.assert_called_once_with("user", "pass")
        smtp.sendmail.assert_called_once()
        self.assertLess(
            smtp.method_calls.index(mock.call.starttls(context=tls_context)),
            smtp.method_calls.index(mock.call.login("user", "pass")),
        )

    def test_upstream_starttls_verification_can_be_disabled(self):
        smtp = mock.MagicMock()
        smtp_cm = mock.MagicMock()
        smtp_cm.__enter__.return_value = smtp

        with mock.patch("sl_smtp_proxy.forwarder.smtplib.SMTP", return_value=smtp_cm):
            UpstreamSmtpForwarder(
                SmtpProxyConfig(
                    upstream_tls_mode="starttls",
                    upstream_tls_verify=False,
                )
            ).forward("sender@example.com", ["recipient@example.com"], self._message())

        context = smtp.starttls.call_args.kwargs["context"]
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)

    def test_upstream_implicit_tls_uses_smtp_ssl(self):
        smtp = mock.MagicMock()
        smtp_cm = mock.MagicMock()
        smtp_cm.__enter__.return_value = smtp
        tls_context = object()

        with mock.patch("sl_smtp_proxy.forwarder.ssl.create_default_context", return_value=tls_context):
            with mock.patch("sl_smtp_proxy.forwarder.smtplib.SMTP_SSL", return_value=smtp_cm) as smtp_ssl_cls:
                with mock.patch("sl_smtp_proxy.forwarder.smtplib.SMTP") as smtp_cls:
                    UpstreamSmtpForwarder(
                        SmtpProxyConfig(upstream_tls_mode="implicit")
                    ).forward("sender@example.com", ["recipient@example.com"], self._message())

        smtp_ssl_cls.assert_called_once_with(
            "host.docker.internal",
            1025,
            timeout=30,
            context=tls_context,
        )
        smtp_cls.assert_not_called()
        smtp.starttls.assert_not_called()
        smtp.ehlo.assert_called_once()
        smtp.sendmail.assert_called_once()

    def test_upstream_tls_mode_env_loads_from_environment(self):
        with mock.patch.dict(
            os.environ,
            {
                "UPSTREAM_SMTP_TLS_MODE": "implicit",
                "UPSTREAM_SMTP_TLS_VERIFY": "false",
            },
            clear=True,
        ):
            config = load_config_from_env()

        self.assertEqual(config.upstream_tls_mode, "implicit")
        self.assertFalse(config.upstream_tls_verify)


class SmtpServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = SmtpProxyServer(local_smtp_config(host="127.0.0.1", port=0, require_auth=False))
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
            local_smtp_config(
                host="127.0.0.1",
                port=self.server.port,
                require_auth=False,
            ),
            timeout_seconds=2,
        )

    async def test_unsafe_remote_config_rejects_before_controller_start(self):
        unsafe_server = SmtpProxyServer(
            SmtpProxyConfig(
                host="0.0.0.0",
                port=0,
                require_auth=False,
                require_tls=True,
                username="smtp-user",
                password="strong-password",
                user_mailboxes={"sender@example.com"},
            )
        )

        with mock.patch("sl_smtp_proxy.smtp_server._SmtpProxyController") as controller_cls:
            with self.assertRaisesRegex(StartupConfigError, "SMTP_PROXY_REQUIRE_AUTH"):
                await unsafe_server.start()

        controller_cls.assert_not_called()
        self.assertIsNone(unsafe_server._controller)

    async def test_mail_from_rejects_sender_outside_user_mailboxes(self):
        sender_server = SmtpProxyServer(
            local_smtp_config(
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
            local_smtp_config(
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

    async def test_mime_from_outside_user_mailboxes_rejects_before_simplelogin_and_upstream(self):
        fake_simplelogin = FakeSimpleLoginHttpServer(self)
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
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        proxy = SmtpProxyServer(
            local_smtp_config(
                simplelogin_base_url=fake_simplelogin.url,
                simplelogin_api_key="test-api-key",
                host="127.0.0.1",
                port=0,
                require_auth=False,
                dry_run=False,
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                user_mailboxes={"sender@example.com"},
                alias_suffix_domains={"@example.net"},
                cache_path=os.path.join(tempdir.name, "cache.sqlite3"),
            ),
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "intruder@example.com"
            msg["To"] = "Alice <alice@example.com>"
            msg["Bcc"] = "orders@example.net"
            msg.set_content("private body")

            with self.assertLogs("sl_smtp_proxy.smtp_server", level="INFO") as captured:
                result = await asyncio.get_running_loop().run_in_executor(
                    None,
                    submit_message,
                    proxy.port,
                    msg,
                    ["alice@example.com", "orders@example.net"],
                    "sender@example.com",
                )

            self.assertEqual(result[0], 550)
            self.assertIn("MIME sender address is not allowed", result[1])
            self.assertEqual(fake_simplelogin.requests, [])
            self.assertEqual(upstream_handler.messages, [])
            self.assertIsNone(proxy.last_plan)
            audit_payloads = [
                json.loads(line.split("audit ", 1)[1])
                for line in captured.output
                if "audit " in line
            ]
            self.assertEqual(audit_payloads[0]["event"], "smtp_mime_sender_rejected")
            self.assertEqual(audit_payloads[0]["header"], "from")
            self.assertEqual(audit_payloads[0]["reason"], "from_not_allowed")
            self.assertNotIn("intruder@example.com", "\n".join(captured.output))
            self.assertNotIn("private body", "\n".join(captured.output))
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_mime_sender_outside_user_mailboxes_rejects_before_simplelogin_and_upstream(self):
        fake_simplelogin = FakeSimpleLoginHttpServer(self)
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
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        proxy = SmtpProxyServer(
            local_smtp_config(
                simplelogin_base_url=fake_simplelogin.url,
                simplelogin_api_key="test-api-key",
                host="127.0.0.1",
                port=0,
                require_auth=False,
                dry_run=False,
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                user_mailboxes={"sender@example.com"},
                alias_suffix_domains={"@example.net"},
                cache_path=os.path.join(tempdir.name, "cache.sqlite3"),
            ),
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["Sender"] = "intruder@example.com"
            msg["To"] = "Alice <alice@example.com>"
            msg["Bcc"] = "orders@example.net"
            msg.set_content("private body")

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                proxy.port,
                msg,
                ["alice@example.com", "orders@example.net"],
                "sender@example.com",
            )

            self.assertEqual(result[0], 550)
            self.assertIn("MIME sender address is not allowed", result[1])
            self.assertEqual(fake_simplelogin.requests, [])
            self.assertEqual(upstream_handler.messages, [])
            self.assertIsNone(proxy.last_plan)
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_message_over_max_size_is_rejected_before_planning(self):
        size_server = SmtpProxyServer(
            local_smtp_config(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                max_message_bytes=128,
            )
        )
        await size_server.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg.set_content("x" * 1024)

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                size_server.port,
                msg,
                ["alice@example.com"],
            )

            self.assertEqual(result[0], 552)
            self.assertIsNone(size_server.last_plan)
        finally:
            await size_server.stop()

    async def test_smtp_submission_uses_injected_resolver_for_rewrite_plan(self):
        rewrite_server = SmtpProxyServer(
            local_smtp_config(
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

    async def test_audit_logs_are_structured_and_do_not_include_message_content(self):
        rewrite_server = SmtpProxyServer(
            local_smtp_config(
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
            msg["Subject"] = "Private subject"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("private body")

            with self.assertLogs("sl_smtp_proxy.smtp_server", level="INFO") as captured:
                result = await asyncio.get_running_loop().run_in_executor(
                    None,
                    submit_message,
                    rewrite_server.port,
                    msg,
                    ["alice@example.com"],
                )

            self.assertEqual(result[0], 550)
            log_text = "\n".join(captured.output)
            self.assertNotIn("Private subject", log_text)
            self.assertNotIn("private body", log_text)
            audit_payloads = [
                json.loads(line.split("audit ", 1)[1])
                for line in captured.output
                if "audit " in line
            ]
            self.assertTrue(audit_payloads)
            self.assertIn("smtp_transform_plan", {payload["event"] for payload in audit_payloads})
            transform_payload = next(
                payload for payload in audit_payloads if payload["event"] == "smtp_transform_plan"
            )
            self.assertEqual(transform_payload["selected_alias"], "s***g@example.com")
            self.assertEqual(transform_payload["rewrite_count"], 1)
        finally:
            await rewrite_server.stop()

    async def test_cc_alias_selects_alias_for_reply_all_with_new_external_recipient(self):
        selected_aliases = []
        rewrite_server = SmtpProxyServer(
            local_smtp_config(
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
            local_smtp_config(
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
            local_smtp_config(
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
            local_smtp_config(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                alias_suffix_domains={"@example.net"},
            ),
            reverse_alias_resolver=lambda recipient, alias: (
                selected_aliases.append(alias) or f"reply+{recipient.split('@', 1)[0]}@simplelogin.co"
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
            local_smtp_config(
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

    async def test_post_transform_verifier_rejects_unsafe_transform_before_upstream(self):
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
            local_smtp_config(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                dry_run=False,
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                alias_suffix_domains={"@example.net"},
            ),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "Alice <alice@example.com>"
            msg["Bcc"] = "orders@example.net"
            msg.set_content("private body")

            with mock.patch(
                "sl_smtp_proxy.smtp_server.apply_transform",
                side_effect=lambda message, plan, config: message,
            ):
                with self.assertLogs("sl_smtp_proxy.smtp_server", level="INFO") as captured:
                    result = await asyncio.get_running_loop().run_in_executor(
                        None,
                        submit_message,
                        proxy.port,
                        msg,
                        ["alice@example.com", "orders@example.net"],
                    )

            self.assertEqual(result[0], 550)
            self.assertIn("post-transform safety verifier", result[1])
            self.assertEqual(upstream_handler.messages, [])
            audit_payloads = [
                json.loads(line.split("audit ", 1)[1])
                for line in captured.output
                if "audit " in line
            ]
            verifier_payload = next(
                payload
                for payload in audit_payloads
                if payload.get("policy") == "post_transform_safety_verifier"
            )
            self.assertEqual(verifier_payload["reason"], "bcc_header_present")
            self.assertNotIn("alice@example.com", "\n".join(captured.output))
            self.assertNotIn("orders@example.net", "\n".join(captured.output))
            self.assertNotIn("private body", "\n".join(captured.output))
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
            local_smtp_config(
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

    async def test_real_simplelogin_and_fake_upstream_integration(self):
        fake_simplelogin = FakeSimpleLoginHttpServer(self)
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
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        proxy = SmtpProxyServer(
            local_smtp_config(
                simplelogin_base_url=fake_simplelogin.url,
                simplelogin_api_key="test-api-key",
                host="127.0.0.1",
                port=0,
                require_auth=False,
                dry_run=False,
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                user_mailboxes={"sender@example.com"},
                alias_suffix_domains={"@example.net"},
                cache_path=os.path.join(tempdir.name, "cache.sqlite3"),
            ),
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "Alice <alice@example.com>"
            msg["Bcc"] = "orders@example.net"
            msg.set_content("private body")

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                proxy.port,
                msg,
                ["alice@example.com", "orders@example.net"],
                "sender@example.com",
            )

            self.assertEqual(result[0], 250)
            self.assertEqual([request[0] for request in fake_simplelogin.requests], ["GET", "GET", "POST"])
            self.assertTrue(all(request[2] == "test-api-key" for request in fake_simplelogin.requests))
            self.assertEqual(
                json.loads(fake_simplelogin.requests[-1][3]),
                {"contact": "alice@example.com"},
            )
            self.assertEqual(len(upstream_handler.messages), 1)
            captured = upstream_handler.messages[0]
            self.assertEqual(captured["mail_from"], "sender@example.com")
            self.assertEqual(captured["rcpt_tos"], ["reply+alice@simplelogin.co"])
            forwarded = BytesParser(policy=policy.default).parsebytes(captured["content"])
            self.assertEqual(forwarded.get("To"), "Alice <reply+alice@simplelogin.co>")
            self.assertIsNone(forwarded.get("Bcc"))
            content = captured["content"].decode("utf-8", errors="replace")
            self.assertNotIn("alice@example.com", content)
            self.assertNotIn("orders@example.net", content)
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
            local_smtp_config(
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
            local_smtp_config(
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
            local_smtp_config(host="127.0.0.1", port=0, require_auth=True, username="user", password="pass")
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
            local_smtp_config(
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

    async def test_auth_failure_is_delayed_and_audited(self):
        auth_server = SmtpProxyServer(
            local_smtp_config(
                host="127.0.0.1",
                port=0,
                require_auth=True,
                username="user",
                password="pass",
                auth_failure_delay_seconds=2.5,
            )
        )
        await auth_server.start()
        try:
            def authenticate():
                payload = base64.b64encode(b"\x00user\x00wrong").decode("ascii")
                with socket.create_connection(("127.0.0.1", auth_server.port), timeout=2) as sock:
                    fileobj = sock.makefile("rwb", buffering=0)
                    read_smtp_response(fileobj)
                    send_smtp_line(fileobj, "EHLO test.local")
                    read_smtp_response(fileobj)
                    send_smtp_line(fileobj, f"AUTH PLAIN {payload}")
                    return read_smtp_response(fileobj)

            with mock.patch("sl_smtp_proxy.smtp_server.time.sleep") as sleep:
                with self.assertLogs("sl_smtp_proxy.smtp_server", level="INFO") as captured:
                    result = await asyncio.get_running_loop().run_in_executor(None, authenticate)

            self.assertEqual(result[0], 535)
            sleep.assert_called_once_with(2.5)
            audit_payloads = [
                json.loads(line.split("audit ", 1)[1])
                for line in captured.output
                if "audit " in line
            ]
            self.assertEqual(audit_payloads[0]["event"], "smtp_auth_failed")
            self.assertEqual(audit_payloads[0]["delay_seconds"], 2.5)
            self.assertNotIn("wrong", "\n".join(captured.output))
        finally:
            await auth_server.stop()

    async def test_auth_login_accepts_configured_credentials(self):
        auth_server = SmtpProxyServer(
            local_smtp_config(
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
            local_smtp_config(
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
            local_smtp_config(
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
            local_smtp_config(
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

    async def test_implicit_tls_auth_false_positive_warning_is_suppressed(self):
        cert_file, key_file = make_test_cert(self)
        auth_server = SmtpProxyServer(
            local_smtp_config(
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
        mail_log = logging.getLogger("mail.log")
        records = []

        class CaptureHandler(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = CaptureHandler(level=logging.WARNING)
        old_level = mail_log.level
        mail_log.addHandler(handler)
        mail_log.setLevel(logging.WARNING)
        try:
            with warnings.catch_warnings(record=True) as captured_warnings:
                warnings.simplefilter("always")
                await auth_server.start()

            messages = [str(item.message) for item in captured_warnings]
            self.assertNotIn(
                "Requiring AUTH while not requiring TLS can lead to security vulnerabilities!",
                messages,
            )
            self.assertNotIn(
                "auth_required == True but auth_require_tls == False",
                [record.getMessage() for record in records],
            )
        finally:
            mail_log.removeHandler(handler)
            mail_log.setLevel(old_level)
            await auth_server.stop()

    async def test_require_tls_refuses_start_until_tls_is_configured(self):
        tls_server = SmtpProxyServer(
            local_smtp_config(host="127.0.0.1", port=0, require_auth=True, require_tls=True)
        )

        with self.assertRaisesRegex(RuntimeError, "SMTP_PROXY_TLS_CERT_FILE"):
            await tls_server.start()


if __name__ == "__main__":
    unittest.main()
