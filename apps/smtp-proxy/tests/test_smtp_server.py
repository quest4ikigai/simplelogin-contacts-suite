import asyncio
import base64
import json
import logging
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import os
import shutil
import smtplib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
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

from sl_smtp_proxy.cache import SQLiteAliasCache
from sl_smtp_proxy.config import SmtpProxyConfig, load_config_from_env
from sl_smtp_proxy.config_validation import StartupConfigError
from sl_smtp_proxy.forwarder import UpstreamForwardingError, UpstreamSmtpForwarder, safe_forwarding_error_fields
from sl_smtp_proxy.healthcheck import check_health
from sl_smtp_proxy.smtp_server import SmtpProxyServer, _forward_fingerprint
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


def submit_message_and_disconnect(port, msg, rcpt_tos, mail_from="sender@example.com"):
    """Like submit_message, but closes the connection the instant the DATA
    terminator is written, without reading the final SMTP response --
    simulating a client that times out or is killed before it sees
    whether the proxy accepted the message.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
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
    finally:
        sock.close()


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


class FakeBulkSimpleLoginHttpServer:
    """Like FakeSimpleLoginHttpServer, but tracks list_contacts page
    requests separately and mints a distinct reverse alias per created
    contact, so bulk-recipient efficiency and correctness can both be
    asserted against the real SimpleLoginClient/ReverseAliasResolver.
    """

    def __init__(self, test_case, existing_contacts=None, fail_contacts_with_status=None):
        self.requests = []
        self.list_contacts_requests = 0
        self.create_contact_requests = 0
        self.aliases = [{"id": 123, "email": "shopping@example.com"}]
        self.contacts = existing_contacts or []
        self.fail_contacts_with_status = fail_contacts_with_status
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                fake.requests.append((self.command, self.path, self.headers.get("Authentication"), None))
                if self.path == "/api/v2/aliases?page_id=0":
                    self._json(200, {"aliases": fake.aliases})
                    return
                if self.path == "/api/aliases/123/contacts?page_id=0":
                    fake.list_contacts_requests += 1
                    if fake.fail_contacts_with_status:
                        self._json(fake.fail_contacts_with_status, {"error": "rate limited"})
                        return
                    self._json(200, {"contacts": fake.contacts})
                    return
                self._json(404, {"error": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                fake.requests.append((self.command, self.path, self.headers.get("Authentication"), body))
                if self.path == "/api/aliases/123/contacts":
                    fake.create_contact_requests += 1
                    contact = json.loads(body)["contact"]
                    _, address = parseaddr(contact)
                    local = (address or contact).split("@", 1)[0]
                    self._json(
                        201,
                        {
                            "contact": {
                                "id": f"created-{local}",
                                "contact": contact,
                                "reverse_alias_address": f"reply+{local}@simplelogin.co",
                            }
                        },
                    )
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


class BlockingResolver:
    """Deterministically "hangs" like a stuck SimpleLogin API call: it
    signals `started` the instant it is entered (so a test can wait for
    it with an Event instead of a sleep) and then blocks until the test
    sets `release`.
    """

    def __init__(self, reverse_alias=lambda recipient: f"reply+{recipient.split('@', 1)[0]}@simplelogin.co"):
        self.started = threading.Event()
        self.release = threading.Event()
        self._reverse_alias = reverse_alias

    def __call__(self, recipient, alias):
        self.started.set()
        self.release.wait(timeout=10)
        return self._reverse_alias(recipient)


class BlockingForwarder:
    """Wraps a real forwarder but blocks inside forward() until released,
    deterministically simulating a slow-but-eventually-successful upstream
    send so a test can control exactly when a client disconnect happens
    relative to the in-flight forward.
    """

    def __init__(self, inner):
        self.inner = inner
        self.started = threading.Event()
        self.release = threading.Event()
        self.completed = threading.Event()

    def forward(self, sender, recipients, message):
        self.started.set()
        self.release.wait(timeout=10)
        try:
            return self.inner.forward(sender, recipients, message)
        finally:
            self.completed.set()


class AlwaysFailsForwarder:
    """A forwarder whose forward() always raises a confirmed
    UpstreamForwardingError, for exercising the "mark_failed" path
    deterministically without depending on a real network failure.
    """

    def __init__(self):
        self.calls = 0

    def forward(self, sender, recipients, message):
        self.calls += 1
        raise UpstreamForwardingError("simulated confirmed forwarding failure")


class AlwaysRaisesUnexpectedForwarder:
    """A forwarder whose forward() raises an exception that is not
    UpstreamForwardingError, simulating a bug or other unexpected failure
    inside forwarding whose effect on upstream delivery is unknown.
    """

    def forward(self, sender, recipients, message):
        raise RuntimeError("simulated unexpected forwarding bug")


def _wait_until(predicate, timeout=2.0, interval=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


async def _wait_until_async(predicate, timeout=2.0, interval=0.02):
    # Polls on the event loop itself (never a worker thread), so it is
    # safe to use against state --- like assertLogs' captured.output ---
    # that the code under test only ever mutates from the event loop.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    return predicate()


def local_smtp_config(**overrides):
    values = {"host": "127.0.0.1", "port": 0}
    values.update(overrides)
    if values.get("dry_run", True):
        values.setdefault("allow_unsafe_local_dry_run", True)
    values.setdefault(
        "cache_path",
        os.path.join(tempfile.mkdtemp(prefix="sl-smtp-proxy-test-"), "cache.sqlite3"),
    )
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

    def test_safe_forwarding_error_fields_never_includes_refused_addresses(self):
        # SMTPRecipientsRefused embeds every refused address (and the
        # upstream's response text) in .recipients. The sanitizer must
        # reduce this to a bounded, address-free summary.
        secret_address = "donor-alice-smith@example.com"
        exc = smtplib.SMTPRecipientsRefused(
            {secret_address: (550, b"mailbox unavailable: " + secret_address.encode())}
        )

        fields = safe_forwarding_error_fields(exc)

        self.assertEqual(fields["error_type"], "SMTPRecipientsRefused")
        self.assertEqual(fields["error_category"], "recipients_refused")
        self.assertEqual(fields["refused_recipient_count"], 1)
        for value in fields.values():
            self.assertNotIn(secret_address, str(value))

    def test_safe_forwarding_error_fields_never_includes_response_text(self):
        # SMTPResponseException (and subclasses like SMTPDataError) carry
        # the raw upstream response text, which can itself echo back an
        # address or other sensitive detail the server was given.
        secret_text = "rejected recipient donor-bob@example.com for policy reasons"
        exc = smtplib.SMTPDataError(554, secret_text.encode())

        fields = safe_forwarding_error_fields(exc)

        self.assertEqual(fields["smtp_code"], 554)
        for value in fields.values():
            self.assertNotIn("donor-bob", str(value))
            self.assertNotIn(secret_text, str(value))

    def test_safe_forwarding_error_fields_categorizes_common_failures(self):
        cases = [
            (smtplib.SMTPAuthenticationError(535, b"auth failed"), "auth_failed"),
            (smtplib.SMTPConnectError(421, b"cannot connect"), "connect_failed"),
            (smtplib.SMTPServerDisconnected("connection closed"), "server_disconnected"),
            (smtplib.SMTPHeloError(500, b"helo rejected"), "smtp_response_error"),
            (TimeoutError("timed out"), "timeout"),
            (ConnectionRefusedError("refused"), "connection_error"),
            (OSError("generic os error"), "network_error"),
            (RuntimeError("some unrelated bug"), "unexpected"),
        ]
        for exc, expected_category in cases:
            with self.subTest(exc_type=type(exc).__name__):
                fields = safe_forwarding_error_fields(exc)
                self.assertEqual(fields["error_category"], expected_category)
                self.assertEqual(fields["error_type"], type(exc).__name__)
                self.assertNotIn(str(exc), " ".join(str(v) for v in fields.values()))

    def test_forward_warning_log_does_not_leak_refused_recipient_addresses(self):
        # End-to-end through UpstreamSmtpForwarder.forward(): even though
        # the upstream rejected a specific recipient by address, the
        # WARNING log it emits must carry only structured, sanitized
        # fields -- never the address itself.
        secret_address = "donor-alice-smith@example.com"
        smtp = mock.MagicMock()
        smtp_cm = mock.MagicMock()
        smtp_cm.__enter__.return_value = smtp
        smtp.sendmail.side_effect = smtplib.SMTPRecipientsRefused(
            {secret_address: (550, b"mailbox unavailable")}
        )

        logger = logging.getLogger("sl_smtp_proxy.forwarder")
        with mock.patch("sl_smtp_proxy.forwarder.smtplib.SMTP", return_value=smtp_cm):
            with self.assertLogs(logger, level="WARNING") as captured:
                with self.assertRaises(UpstreamForwardingError) as raised:
                    UpstreamSmtpForwarder(SmtpProxyConfig()).forward(
                        "sender@example.com", [secret_address], self._message()
                    )

        for line in captured.output:
            self.assertNotIn(secret_address, line)
        self.assertIn("error_category=recipients_refused", captured.output[0])
        self.assertIn("refused_recipient_count=1", captured.output[0])
        # The client-visible message is a fixed, generic string -- never
        # derived from the exception's own text.
        self.assertNotIn(secret_address, raised.exception.public_message)


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


    async def test_reverse_alias_plus_new_recipient_reply_end_to_end(self):
        # Regression for the reported incident: a reply where an existing
        # reverse alias was manually moved into To alongside a newly added
        # ordinary recipient, with the sender's own alias left in Cc. The
        # ordinary recipient must be converted to a reverse alias end to
        # end, not forwarded to Proton Bridge literally.
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
                known_reverse_aliases={"reply+existing@simplelogin.co"},
                manual_simplelogin_aliases={"shopping@example.com"},
            ),
            reverse_alias_resolver=lambda recipient, alias: f"reply+{recipient.split('@', 1)[0]}@simplelogin.co",
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "reply+existing@simplelogin.co, newperson@example.com"
            msg["Cc"] = "shopping@example.com"
            msg.set_content("private body")

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                proxy.port,
                msg,
                [
                    "reply+existing@simplelogin.co",
                    "newperson@example.com",
                    "shopping@example.com",
                ],
            )

            self.assertEqual(result[0], 250)
            self.assertEqual(len(upstream_handler.messages), 1)
            captured = upstream_handler.messages[0]
            self.assertEqual(
                captured["rcpt_tos"],
                ["reply+existing@simplelogin.co", "reply+newperson@simplelogin.co"],
            )
            forwarded = BytesParser(policy=policy.default).parsebytes(captured["content"])
            self.assertEqual(
                forwarded.get("To"),
                "reply+existing@simplelogin.co, reply+newperson@simplelogin.co",
            )
            self.assertIsNone(forwarded.get("Cc"))
            content = captured["content"].decode("utf-8", errors="replace")
            self.assertNotIn("newperson@example.com", content)
            self.assertNotIn("shopping@example.com", content)
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_one_recipient_resolver_failure_rejects_entire_message(self):
        # Fail-closed / all-or-nothing invariant: if any recipient's
        # reverse-alias lookup fails, nothing should be forwarded upstream,
        # even though another recipient in the same message resolved fine
        # and an existing reverse alias just needed to be kept.
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

        def flaky_resolver(recipient, alias):
            if recipient == "unlucky@example.com":
                raise RuntimeError("simplelogin api unavailable")
            return f"reply+{recipient.split('@', 1)[0]}@simplelogin.co"

        proxy = SmtpProxyServer(
            local_smtp_config(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                dry_run=False,
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                known_reverse_aliases={"reply+existing@simplelogin.co"},
                manual_simplelogin_aliases={"shopping@example.com"},
            ),
            reverse_alias_resolver=flaky_resolver,
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "reply+existing@simplelogin.co, lucky@example.com, unlucky@example.com"
            msg["Cc"] = "shopping@example.com"
            msg.set_content("private body")

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                proxy.port,
                msg,
                [
                    "reply+existing@simplelogin.co",
                    "lucky@example.com",
                    "unlucky@example.com",
                    "shopping@example.com",
                ],
            )

            self.assertEqual(result[0], 550)
            self.assertEqual(upstream_handler.messages, [])
            self.assertTrue(proxy.last_plan.rejected)
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

    async def test_bulk_recipients_resolve_with_single_contact_list_fetch(self):
        # Regression for the reported classroom-announcement hang: a
        # 40-50 recipient message must not download the alias's full
        # contact list once per recipient.
        fake_simplelogin = FakeBulkSimpleLoginHttpServer(self)
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
                cache_path=os.path.join(tempdir.name, "cache.sqlite3"),
            ),
        )
        await proxy.start()
        try:
            recipients = [f"person{i}@example.org" for i in range(45)]
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = ", ".join(recipients)
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                proxy.port,
                msg,
                recipients,
            )

            self.assertEqual(result[0], 250)
            self.assertEqual(fake_simplelogin.list_contacts_requests, 1)
            self.assertEqual(fake_simplelogin.create_contact_requests, 45)
            self.assertEqual(len(upstream_handler.messages), 1)
            captured_rcpt_tos = upstream_handler.messages[0]["rcpt_tos"]
            self.assertEqual(len(captured_rcpt_tos), 45)
            self.assertEqual(len(set(captured_rcpt_tos)), 45)
            self.assertTrue(all(addr.endswith("@simplelogin.co") for addr in captured_rcpt_tos))
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_bulk_recipients_with_cache_hits_skip_api_entirely(self):
        fake_simplelogin = FakeBulkSimpleLoginHttpServer(self)
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
        cache_path = os.path.join(tempdir.name, "cache.sqlite3")
        cache = SQLiteAliasCache(cache_path)
        cache.upsert_alias("123", "shopping@example.com")
        cached_recipients = [f"cached{i}@example.org" for i in range(20)]
        for i, recipient in enumerate(cached_recipients):
            cache.upsert_contact(str(i), "123", recipient, recipient, f"reply+cached{i}@simplelogin.co")
        new_recipients = [f"new{i}@example.org" for i in range(25)]

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
                cache_path=cache_path,
            ),
        )
        await proxy.start()
        try:
            recipients = cached_recipients + new_recipients
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = ", ".join(recipients)
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            with self.assertLogs("sl_smtp_proxy.smtp_server", level="INFO") as captured:
                result = await asyncio.get_running_loop().run_in_executor(
                    None,
                    submit_message,
                    proxy.port,
                    msg,
                    recipients,
                )

            self.assertEqual(result[0], 250)
            self.assertEqual(fake_simplelogin.list_contacts_requests, 1)
            self.assertEqual(fake_simplelogin.create_contact_requests, 25)
            audit_payloads = [
                json.loads(line.split("audit ", 1)[1])
                for line in captured.output
                if "audit " in line
            ]
            transform_payload = next(
                payload for payload in audit_payloads if payload["event"] == "smtp_transform_plan"
            )
            self.assertEqual(transform_payload["cache_hit_count"], 20)
            self.assertEqual(transform_payload["cache_miss_count"], 25)
            self.assertEqual(transform_payload["contacts_created"], 25)
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_simplelogin_rate_limit_during_bulk_resolve_fails_closed(self):
        fake_simplelogin = FakeBulkSimpleLoginHttpServer(self, fail_contacts_with_status=429)
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
                cache_path=os.path.join(tempdir.name, "cache.sqlite3"),
            ),
        )
        await proxy.start()
        try:
            recipients = [f"person{i}@example.org" for i in range(5)]
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = ", ".join(recipients)
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            result = await asyncio.get_running_loop().run_in_executor(
                None,
                submit_message,
                proxy.port,
                msg,
                recipients,
            )

            self.assertEqual(result[0], 550)
            self.assertEqual(upstream_handler.messages, [])
            self.assertTrue(proxy.last_plan.rejected)
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_server_remains_responsive_while_recipient_resolution_is_blocked(self):
        blocking_resolver = BlockingResolver()
        proxy = SmtpProxyServer(
            local_smtp_config(host="127.0.0.1", port=0, require_auth=False),
            reverse_alias_resolver=blocking_resolver,
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            loop = asyncio.get_running_loop()
            slow_send = loop.run_in_executor(
                None, submit_message, proxy.port, msg, ["alice@example.com"]
            )

            # Deterministically wait until the blocked resolver call has
            # actually started inside the resolver's worker thread, rather
            # than guessing at a sleep duration.
            started = await loop.run_in_executor(None, blocking_resolver.started.wait, 2.0)
            self.assertTrue(started, "resolver never started; cannot exercise the blocking scenario")

            # While that first submission is stuck in recipient
            # resolution, a brand-new connection/health probe must still
            # be served promptly -- proving the event loop itself was
            # never blocked.
            probe_config = SmtpProxyConfig(host="127.0.0.1", port=proxy.port, require_auth=False)
            await asyncio.wait_for(
                loop.run_in_executor(None, check_health, probe_config, 2.0),
                timeout=3.0,
            )
            probe_result = await asyncio.wait_for(
                loop.run_in_executor(None, mail_from_response, proxy.port, "sender@example.com"),
                timeout=3.0,
            )
            self.assertEqual(probe_result[0], 250)

            blocking_resolver.release.set()
            result = await asyncio.wait_for(slow_send, timeout=5.0)
            self.assertEqual(result[0], 550)
            self.assertIn("dry-run", result[1])
        finally:
            blocking_resolver.release.set()
            await proxy.stop()

    async def test_client_disconnect_during_resolution_does_not_forward(self):
        blocking_resolver = BlockingResolver()
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
            ),
            reverse_alias_resolver=blocking_resolver,
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            loop = asyncio.get_running_loop()
            with self.assertLogs("sl_smtp_proxy.smtp_server", level="INFO") as captured:
                disconnecting_send = loop.run_in_executor(
                    None,
                    submit_message_and_disconnect,
                    proxy.port,
                    msg,
                    ["alice@example.com"],
                )
                started = await loop.run_in_executor(None, blocking_resolver.started.wait, 2.0)
                self.assertTrue(started)
                await asyncio.wait_for(disconnecting_send, timeout=3.0)
                blocking_resolver.release.set()

                def _disconnect_logged():
                    return any(
                        "smtp_client_disconnected_during_processing" in line
                        for line in captured.output
                    )

                self.assertTrue(
                    await _wait_until_async(_disconnect_logged, timeout=2.0),
                    "expected a disconnect-during-processing audit event",
                )

            audit_payloads = [
                json.loads(line.split("audit ", 1)[1])
                for line in captured.output
                if "audit " in line
            ]
            disconnect_events = [
                payload
                for payload in audit_payloads
                if payload["event"] == "smtp_client_disconnected_during_processing"
            ]
            self.assertEqual(disconnect_events[0]["phase"], "resolution")
            self.assertEqual(upstream_handler.messages, [])
        finally:
            blocking_resolver.release.set()
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_client_disconnect_during_forwarding_still_records_outcome(self):
        # Regression for the reported incident: the upstream SMTP send
        # completed successfully even though the client had already
        # timed out and disconnected, and no forwarding audit event was
        # ever logged. The forwarding task must run to completion and
        # log its real outcome regardless of the client's fate.
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
        real_forwarder = UpstreamSmtpForwarder(
            SmtpProxyConfig(upstream_host="127.0.0.1", upstream_port=upstream_port)
        )
        blocking_forwarder = BlockingForwarder(real_forwarder)
        proxy = SmtpProxyServer(
            local_smtp_config(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                dry_run=False,
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
            ),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
            forwarder=blocking_forwarder,
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            loop = asyncio.get_running_loop()
            with self.assertLogs("sl_smtp_proxy.smtp_server", level="INFO") as captured:
                disconnecting_send = loop.run_in_executor(
                    None,
                    submit_message_and_disconnect,
                    proxy.port,
                    msg,
                    ["alice@example.com"],
                )

                started = await loop.run_in_executor(None, blocking_forwarder.started.wait, 2.0)
                self.assertTrue(started, "forward() never started")
                await asyncio.wait_for(disconnecting_send, timeout=3.0)

                # The client is gone, but the in-flight forward must not
                # be abandoned: release it and require it to still
                # complete and still hand the message to upstream.
                blocking_forwarder.release.set()
                completed = await loop.run_in_executor(None, blocking_forwarder.completed.wait, 3.0)
                self.assertTrue(completed, "forward() never completed after being released")

                def _forwarded_logged():
                    return any(
                        '"event":"smtp_message_forwarded"' in line for line in captured.output
                    )

                self.assertTrue(
                    await _wait_until_async(_forwarded_logged, timeout=2.0),
                    "expected a definitive smtp_message_forwarded audit event after disconnect",
                )

            self.assertEqual(len(upstream_handler.messages), 1)
            audit_payloads = [
                json.loads(line.split("audit ", 1)[1])
                for line in captured.output
                if "audit " in line
            ]
            disconnect_events = [
                payload
                for payload in audit_payloads
                if payload["event"] == "smtp_client_disconnected_during_processing"
            ]
            forwarded_events = [
                payload for payload in audit_payloads if payload["event"] == "smtp_message_forwarded"
            ]
            self.assertEqual(disconnect_events[0]["phase"], "forwarding")
            self.assertEqual(len(forwarded_events), 1)
            self.assertEqual(
                disconnect_events[0]["correlation_id"],
                forwarded_events[0]["correlation_id"],
            )
        finally:
            blocking_forwarder.release.set()
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_unexpected_forwarding_exception_returns_temporary_failure_and_is_audited(self):
        # An unexpected failure inside forwarding (not a confirmed
        # UpstreamForwardingError) must not disappear silently, and must
        # not be reported as success or as a confirmed, permanent
        # failure: its effect on upstream delivery is unknown.
        proxy = SmtpProxyServer(
            local_smtp_config(host="127.0.0.1", port=0, require_auth=False, dry_run=False),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
            forwarder=AlwaysRaisesUnexpectedForwarder(),
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            with self.assertLogs("sl_smtp_proxy.smtp_server", level="INFO") as captured:
                result = await asyncio.get_running_loop().run_in_executor(
                    None, submit_message, proxy.port, msg, ["alice@example.com"]
                )

            self.assertEqual(result[0], 451)

            audit_payloads = [
                json.loads(line.split("audit ", 1)[1]) for line in captured.output if "audit " in line
            ]
            unknown_events = [
                payload for payload in audit_payloads if payload["event"] == "smtp_forwarding_outcome_unknown"
            ]
            self.assertEqual(len(unknown_events), 1)
            self.assertEqual(unknown_events[0]["policy"], "internal_error")
            self.assertEqual(unknown_events[0]["error_type"], "RuntimeError")
            self.assertIn("correlation_id", unknown_events[0])
            # Never leak the raw exception text (it could contain
            # addresses, content, or credentials) -- only the structured,
            # sanitized fields from safe_forwarding_error_fields.
            for line in captured.output:
                self.assertNotIn("simulated unexpected forwarding bug", line)
        finally:
            await proxy.stop()

    async def test_unexpected_forwarding_exception_after_disconnect_still_logs_audit_event(self):
        # Same regression shape as the client-disconnect-during-forwarding
        # test above, but for an unexpected (non-UpstreamForwardingError)
        # exception: the outcome must still be observable, correlated to
        # the same submission, even though nobody is left to read
        # handle_DATA's return value.
        unexpected_forwarder = AlwaysRaisesUnexpectedForwarder()
        blocking_forwarder = BlockingForwarder(unexpected_forwarder)
        proxy = SmtpProxyServer(
            local_smtp_config(host="127.0.0.1", port=0, require_auth=False, dry_run=False),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
            forwarder=blocking_forwarder,
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            loop = asyncio.get_running_loop()
            with self.assertLogs("sl_smtp_proxy.smtp_server", level="INFO") as captured:
                disconnecting_send = loop.run_in_executor(
                    None, submit_message_and_disconnect, proxy.port, msg, ["alice@example.com"]
                )
                started = await loop.run_in_executor(None, blocking_forwarder.started.wait, 2.0)
                self.assertTrue(started, "forward() never started")
                await asyncio.wait_for(disconnecting_send, timeout=3.0)

                blocking_forwarder.release.set()
                completed = await loop.run_in_executor(None, blocking_forwarder.completed.wait, 3.0)
                self.assertTrue(completed, "forward() never completed after being released")

                def _unknown_outcome_logged():
                    return any(
                        '"event":"smtp_forwarding_outcome_unknown"' in line for line in captured.output
                    )

                self.assertTrue(
                    await _wait_until_async(_unknown_outcome_logged, timeout=2.0),
                    "expected a smtp_forwarding_outcome_unknown audit event after disconnect",
                )

            audit_payloads = [
                json.loads(line.split("audit ", 1)[1]) for line in captured.output if "audit " in line
            ]
            disconnect_events = [
                payload
                for payload in audit_payloads
                if payload["event"] == "smtp_client_disconnected_during_processing"
            ]
            unknown_events = [
                payload for payload in audit_payloads if payload["event"] == "smtp_forwarding_outcome_unknown"
            ]
            self.assertEqual(len(unknown_events), 1)
            self.assertEqual(
                disconnect_events[0]["correlation_id"], unknown_events[0]["correlation_id"]
            )
            for line in captured.output:
                self.assertNotIn("simulated unexpected forwarding bug", line)
        finally:
            blocking_forwarder.release.set()
            await proxy.stop()

    async def test_duplicate_submission_of_a_completed_send_is_not_resent(self):
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
            ),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["Message-Id"] = "<fixed-id@example.com>"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            first = await asyncio.get_running_loop().run_in_executor(
                None, submit_message, proxy.port, msg, ["alice@example.com"]
            )
            second = await asyncio.get_running_loop().run_in_executor(
                None, submit_message, proxy.port, msg, ["alice@example.com"]
            )

            self.assertEqual(first[0], 250)
            # The first send already completed successfully: a resubmission
            # of the exact same message is reported as already-accepted
            # (250) rather than forwarded a second time, and rather than
            # being permanently rejected (550) as if it were an error.
            self.assertEqual(second[0], 250)
            self.assertIn("already accepted", second[1].lower())
            self.assertEqual(len(upstream_handler.messages), 1)
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_resubmission_with_different_message_id_is_not_suppressed(self):
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
            ),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
        )
        await proxy.start()
        try:
            def message(message_id):
                msg = EmailMessage()
                msg["From"] = "sender@example.com"
                msg["To"] = "alice@example.com"
                msg["Message-Id"] = message_id
                msg["X-SimpleLogin-Alias"] = "shopping@example.com"
                msg.set_content("classroom announcement")
                return msg

            first = await asyncio.get_running_loop().run_in_executor(
                None, submit_message, proxy.port, message("<one@example.com>"), ["alice@example.com"]
            )
            second = await asyncio.get_running_loop().run_in_executor(
                None, submit_message, proxy.port, message("<two@example.com>"), ["alice@example.com"]
            )

            self.assertEqual(first[0], 250)
            self.assertEqual(second[0], 250)
            self.assertEqual(len(upstream_handler.messages), 2)
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_concurrent_retry_while_first_send_still_in_flight_is_suppressed(self):
        # Regression for the race Codex flagged: a client that disconnects
        # during a slow upstream send and immediately retries can have both
        # submissions pass a duplicate check before either one finishes
        # forwarding. The fingerprint must be reserved atomically up front
        # (before forwarding even starts), not only recorded after a
        # successful send, so the retry is deferred while the first send is
        # still blocked in flight -- not merely after it completes. It must
        # get a temporary (451) response, not a permanent (550) one: the
        # first send might still fail, in which case this exact retry
        # should be allowed through (see the follow-up finding on reserving
        # fingerprints without permanently rejecting legitimate retries).
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
        real_forwarder = UpstreamSmtpForwarder(
            SmtpProxyConfig(upstream_host="127.0.0.1", upstream_port=upstream_port)
        )
        blocking_forwarder = BlockingForwarder(real_forwarder)
        proxy = SmtpProxyServer(
            local_smtp_config(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                dry_run=False,
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
            ),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
            forwarder=blocking_forwarder,
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["Message-Id"] = "<fixed-id@example.com>"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            loop = asyncio.get_running_loop()
            first_send = loop.run_in_executor(
                None, submit_message, proxy.port, msg, ["alice@example.com"]
            )

            started = await loop.run_in_executor(None, blocking_forwarder.started.wait, 2.0)
            self.assertTrue(started, "forward() never started")

            # The first forward is still blocked -- nothing has been marked
            # as successfully forwarded yet. The identical retry must be
            # deferred (temporary failure) right away, without hanging and
            # without being forwarded a second time, but must NOT be
            # permanently rejected: the first attempt's outcome isn't known
            # yet, so a 550 here would be wrong if it later fails.
            second = await asyncio.wait_for(
                loop.run_in_executor(None, submit_message, proxy.port, msg, ["alice@example.com"]),
                timeout=3.0,
            )
            # Release the blocked forward immediately, before asserting on
            # `second`, so a failed assertion here never leaves a
            # background thread stuck waiting on the upstream connection
            # past the end of this test (which would otherwise delay the
            # *next* test's asyncio teardown by however long that thread
            # takes to unblock).
            blocking_forwarder.release.set()
            self.assertEqual(second[0], 451)
            self.assertIn("retry", second[1].lower())

            completed = await loop.run_in_executor(None, blocking_forwarder.completed.wait, 3.0)
            self.assertTrue(completed, "forward() never completed after being released")
            first = await asyncio.wait_for(first_send, timeout=3.0)

            self.assertEqual(first[0], 250)
            self.assertEqual(len(upstream_handler.messages), 1)
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_pending_then_completed_after_first_send_succeeds(self):
        # "First submission succeeds after the second encounters its
        # pending state": the concurrent retry must see a temporary
        # deferral while the first is in flight, and a *later* identical
        # resubmission (after the first completes) must be reported as
        # already-delivered rather than forwarded a second time.
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
        real_forwarder = UpstreamSmtpForwarder(
            SmtpProxyConfig(upstream_host="127.0.0.1", upstream_port=upstream_port)
        )
        blocking_forwarder = BlockingForwarder(real_forwarder)
        proxy = SmtpProxyServer(
            local_smtp_config(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                dry_run=False,
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
            ),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
            forwarder=blocking_forwarder,
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["Message-Id"] = "<pending-then-completed@example.com>"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            loop = asyncio.get_running_loop()
            first_send = loop.run_in_executor(
                None, submit_message, proxy.port, msg, ["alice@example.com"]
            )
            started = await loop.run_in_executor(None, blocking_forwarder.started.wait, 2.0)
            self.assertTrue(started, "forward() never started")

            pending = await asyncio.wait_for(
                loop.run_in_executor(None, submit_message, proxy.port, msg, ["alice@example.com"]),
                timeout=3.0,
            )
            blocking_forwarder.release.set()
            self.assertEqual(pending[0], 451)

            first = await asyncio.wait_for(first_send, timeout=3.0)
            self.assertEqual(first[0], 250)

            after = await loop.run_in_executor(
                None, submit_message, proxy.port, msg, ["alice@example.com"]
            )
            self.assertEqual(after[0], 250)
            self.assertIn("already accepted", after[1].lower())
            self.assertEqual(len(upstream_handler.messages), 1)
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_pending_then_retryable_after_first_send_fails(self):
        # "First submission fails after the second encounters its pending
        # state": the concurrent retry must still see a temporary
        # deferral (not an immediate failure or success guess), and once
        # the first attempt is confirmed to have failed, a resubmission of
        # the exact same message must be allowed to actually retry.
        failing_forwarder = AlwaysFailsForwarder()
        blocking_forwarder = BlockingForwarder(failing_forwarder)
        proxy = SmtpProxyServer(
            local_smtp_config(host="127.0.0.1", port=0, require_auth=False, dry_run=False),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
            forwarder=blocking_forwarder,
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["Message-Id"] = "<pending-then-failed@example.com>"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            loop = asyncio.get_running_loop()
            first_send = loop.run_in_executor(
                None, submit_message, proxy.port, msg, ["alice@example.com"]
            )
            started = await loop.run_in_executor(None, blocking_forwarder.started.wait, 2.0)
            self.assertTrue(started, "forward() never started")

            pending = await asyncio.wait_for(
                loop.run_in_executor(None, submit_message, proxy.port, msg, ["alice@example.com"]),
                timeout=3.0,
            )
            blocking_forwarder.release.set()
            self.assertEqual(pending[0], 451)

            first = await asyncio.wait_for(first_send, timeout=3.0)
            self.assertEqual(first[0], 550)

            # Nothing was delivered, so this retry must actually reach
            # forwarding again (not be answered from a cached rejection):
            # the distinctive failure text and the call count both prove
            # forward() ran a second time.
            retry = await loop.run_in_executor(
                None, submit_message, proxy.port, msg, ["alice@example.com"]
            )
            self.assertEqual(retry[0], 550)
            self.assertIn("simulated confirmed forwarding failure", retry[1])
            self.assertEqual(failing_forwarder.calls, 2)
        finally:
            await proxy.stop()

    async def test_retry_after_confirmed_upstream_failure_is_forwarded_again(self):
        dead_port = free_port()
        proxy = SmtpProxyServer(
            local_smtp_config(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                dry_run=False,
                upstream_host="127.0.0.1",
                upstream_port=dead_port,
            ),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
        )
        await proxy.start()
        upstream = None
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["Message-Id"] = "<confirmed-failure-retry@example.com>"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            first = await asyncio.get_running_loop().run_in_executor(
                None, submit_message, proxy.port, msg, ["alice@example.com"]
            )
            self.assertEqual(first[0], 550)
            self.assertIn("Upstream SMTP unavailable", first[1])

            # Nothing was delivered. Bring a real upstream server up on
            # the exact port the proxy is already configured for, then
            # resubmit the identical message: this must be allowed to
            # actually retry forwarding rather than being rejected as a
            # duplicate of a message that was never sent.
            upstream_handler = CaptureUpstreamHandler()
            upstream = Controller(
                upstream_handler,
                hostname="127.0.0.1",
                port=dead_port,
                decode_data=False,
                ready_timeout=5.0,
            )
            upstream.start()

            second = await asyncio.get_running_loop().run_in_executor(
                None, submit_message, proxy.port, msg, ["alice@example.com"]
            )
            self.assertEqual(second[0], 250)
            self.assertEqual(len(upstream_handler.messages), 1)
        finally:
            await proxy.stop()
            if upstream is not None:
                upstream.stop(no_assert=True)

    async def test_abandoned_reservation_defers_then_recovers_after_grace_period(self):
        # Simulates a crash: a reservation is made for a fingerprint and
        # then simply never resolved (no renewal, no mark_forwarded/
        # mark_failed), as if the process died mid-send. A short lease and
        # grace period make this test fast without any timestamp hacking.
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
                duplicate_reservation_lease_seconds=1,
                duplicate_reservation_abandoned_grace_seconds=1,
            ),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["Message-Id"] = "<abandoned-recovery@example.com>"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            fingerprint = _forward_fingerprint(
                "sender@example.com", ["reply+alice@simplelogin.co"], msg
            )
            proxy.handler._dedup_cache.try_reserve_forwarding(
                fingerprint,
                "crashed-attempt",
                suppression_window_seconds=3600,
                lease_seconds=1,
                abandoned_grace_seconds=1,
            )

            # Lease expired (>1s) but still within the abandoned-grace
            # window (<2s total): defer, and the audit trail must say so
            # explicitly rather than looking like an ordinary in-flight
            # duplicate.
            await asyncio.sleep(1.2)
            with self.assertLogs("sl_smtp_proxy.smtp_server", level="INFO") as captured:
                deferred = await asyncio.get_running_loop().run_in_executor(
                    None, submit_message, proxy.port, msg, ["alice@example.com"]
                )
            self.assertEqual(deferred[0], 451)
            self.assertTrue(
                any("duplicate_reservation_abandoned" in line for line in captured.output)
            )
            self.assertEqual(upstream_handler.messages, [])

            # Beyond lease + grace entirely: the proxy gives up waiting on
            # the crashed attempt and reclaims the fingerprint for real.
            await asyncio.sleep(1.2)
            recovered = await asyncio.get_running_loop().run_in_executor(
                None, submit_message, proxy.port, msg, ["alice@example.com"]
            )
            self.assertEqual(recovered[0], 250)
            self.assertEqual(len(upstream_handler.messages), 1)
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_slow_genuine_forward_renews_lease_and_is_not_abandoned(self):
        # A forwarding operation that remains in progress beyond the
        # normal reservation lease must not look abandoned just because
        # it is slow: as long as it is still alive and renewing its
        # lease, a concurrent duplicate must keep seeing "in_flight", and
        # must never see "abandoned" or be allowed to forward itself.
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
        real_forwarder = UpstreamSmtpForwarder(
            SmtpProxyConfig(upstream_host="127.0.0.1", upstream_port=upstream_port)
        )
        blocking_forwarder = BlockingForwarder(real_forwarder)
        proxy = SmtpProxyServer(
            local_smtp_config(
                host="127.0.0.1",
                port=0,
                require_auth=False,
                dry_run=False,
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                duplicate_reservation_lease_seconds=1,
                duplicate_reservation_abandoned_grace_seconds=30,
            ),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
            forwarder=blocking_forwarder,
        )
        await proxy.start()
        try:
            msg = EmailMessage()
            msg["From"] = "sender@example.com"
            msg["To"] = "alice@example.com"
            msg["Message-Id"] = "<slow-but-alive@example.com>"
            msg["X-SimpleLogin-Alias"] = "shopping@example.com"
            msg.set_content("classroom announcement")

            loop = asyncio.get_running_loop()
            first_send = loop.run_in_executor(
                None, submit_message, proxy.port, msg, ["alice@example.com"]
            )
            started = await loop.run_in_executor(None, blocking_forwarder.started.wait, 2.0)
            self.assertTrue(started, "forward() never started")

            # Outlive the 1-second lease (by more than one renewal
            # interval) while still blocked -- a crashed process could
            # never do this, since nothing would be left alive to renew.
            # Stay under submit_message's 2s client socket timeout, since
            # first_send's own connection is still open and unanswered.
            await asyncio.sleep(1.5)
            with self.assertLogs("sl_smtp_proxy.smtp_server", level="INFO") as captured:
                still_pending = await asyncio.wait_for(
                    loop.run_in_executor(None, submit_message, proxy.port, msg, ["alice@example.com"]),
                    timeout=3.0,
                )
            self.assertEqual(still_pending[0], 451)
            self.assertTrue(any("duplicate_in_flight" in line for line in captured.output))
            self.assertFalse(
                any("duplicate_reservation_abandoned" in line for line in captured.output)
            )

            blocking_forwarder.release.set()
            first = await asyncio.wait_for(first_send, timeout=3.0)
            self.assertEqual(first[0], 250)
            self.assertEqual(len(upstream_handler.messages), 1)
        finally:
            await proxy.stop()
            upstream.stop(no_assert=True)

    async def test_require_tls_refuses_start_until_tls_is_configured(self):
        tls_server = SmtpProxyServer(
            local_smtp_config(host="127.0.0.1", port=0, require_auth=True, require_tls=True)
        )

        with self.assertRaisesRegex(RuntimeError, "SMTP_PROXY_TLS_CERT_FILE"):
            await tls_server.start()


if __name__ == "__main__":
    unittest.main()
