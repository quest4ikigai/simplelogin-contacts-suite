import asyncio
import json
import os
import signal
import sys
import unittest
from email.message import EmailMessage

APP_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
CORE_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "alias-routing-core", "src")
SIMPLELOGIN_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "simplelogin-client", "src")
sys.path.insert(0, os.path.abspath(APP_SRC))
sys.path.insert(0, os.path.abspath(CORE_SRC))
sys.path.insert(0, os.path.abspath(SIMPLELOGIN_SRC))
sys.path.insert(0, os.path.dirname(__file__))

from sl_smtp_proxy.main import run_until_shutdown_signal
from sl_smtp_proxy.smtp_server import SmtpProxyServer

from test_smtp_server import (  # noqa: E402  (path setup must come first)
    AlwaysSucceedsForwarder,
    BlockingForwarder,
    _wait_until_async,
    local_smtp_config,
    read_smtp_response,
    send_smtp_line,
    submit_message_and_disconnect,
)
import socket


def _submit_over_new_connection(port, msg, rcpt_tos, mail_from="sender@example.com"):
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


class _OpenSmtpSession:
    """A real SMTP connection held open through EHLO/MAIL/RCPT/DATA, so a
    test can send the DATA payload at a time of its own choosing --
    used to simulate a session that was established *before* shutdown
    began, then tries to submit a message *during* shutdown.
    """

    def __init__(self, port, mail_from="sender@example.com", rcpt_tos=("alice@example.com",)):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=2)
        self.fileobj = self.sock.makefile("rwb", buffering=0)
        read_smtp_response(self.fileobj)
        send_smtp_line(self.fileobj, "EHLO test.local")
        read_smtp_response(self.fileobj)
        send_smtp_line(self.fileobj, f"MAIL FROM:<{mail_from}>")
        read_smtp_response(self.fileobj)
        for rcpt_to in rcpt_tos:
            send_smtp_line(self.fileobj, f"RCPT TO:<{rcpt_to}>")
            read_smtp_response(self.fileobj)

    def send_data(self, msg):
        send_smtp_line(self.fileobj, "DATA")
        read_smtp_response(self.fileobj)
        self.fileobj.write(msg.as_bytes().replace(b"\n", b"\r\n") + b"\r\n.\r\n")
        self.fileobj.flush()
        return read_smtp_response(self.fileobj)

    def close(self):
        self.sock.close()


def _classroom_message(alias="shopping@example.com", to="alice@example.com"):
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = to
    msg["X-SimpleLogin-Alias"] = alias
    msg.set_content("classroom announcement")
    return msg


class ProductionShutdownTests(unittest.IsolatedAsyncioTestCase):
    """Exercises the actual production termination path
    (run_until_shutdown_signal, driven by real SIGTERM/SIGINT delivery)
    rather than calling SmtpProxyServer.stop() directly, per Codex's
    finding that the original drain protection was implemented and
    tested at the SmtpProxyServer level but never wired into main.py's
    actual process lifecycle.
    """

    async def asyncSetUp(self):
        self.blocking_forwarder = BlockingForwarder(AlwaysSucceedsForwarder())
        self.server = SmtpProxyServer(
            local_smtp_config(host="127.0.0.1", port=0, require_auth=False, dry_run=False),
            reverse_alias_resolver=lambda recipient, alias: "reply+alice@simplelogin.co",
            forwarder=self.blocking_forwarder,
        )
        await self.server.start()
        self.run_task = asyncio.ensure_future(run_until_shutdown_signal(self.server))
        # Give the freshly-created task a scheduling tick so its signal
        # handlers are registered before any test body sends one --
        # otherwise os.kill() below could race ahead of registration
        # and hit Python's default SIGTERM disposition instead.
        await asyncio.sleep(0)

    async def asyncTearDown(self):
        self.blocking_forwarder.release.set()
        if not self.run_task.done():
            # Cancel directly rather than sending a second real
            # SIGTERM: run_until_shutdown_signal removes its signal
            # handlers as soon as the first shutdown signal is
            # received, before server.stop() itself (which can take a
            # while draining) runs -- a real SIGTERM landing after a
            # failed assertion left run_task still inside that stop()
            # call would have no handler to catch it and would kill
            # this entire test process via Python's default
            # disposition, exactly like the bug this test module
            # exists to catch, just aimed at the test runner instead.
            self.run_task.cancel()
            try:
                await asyncio.wait_for(self.run_task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass
        # Guard against a test failing before the server ever received
        # a shutdown signal -- leaving the real OS-level listener
        # bound would otherwise leak across tests.
        if self.server._controller is not None:
            await self.server.stop()

    async def test_sigterm_during_forwarding_drains_before_exiting(self):
        # Scenario A: start the application via the actual production
        # lifecycle (run_until_shutdown_signal, not server.stop()
        # directly), begin a deliberately-blocked forward, send a real
        # SIGTERM, and confirm the process does not abandon it: the
        # forward completes, its terminal audit event and dedup state
        # are recorded, and only then does the production run loop
        # return.
        loop = asyncio.get_running_loop()
        msg = _classroom_message()

        with self.assertLogs("sl_smtp_proxy.smtp_server", level="INFO") as captured:
            send_future = loop.run_in_executor(
                None,
                _submit_over_new_connection,
                self.server.port,
                msg,
                ["alice@example.com"],
            )
            started = await loop.run_in_executor(
                None, self.blocking_forwarder.started.wait, 2.0
            )
            self.assertTrue(started, "forward() never started")

            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.sleep(0.2)
            self.assertFalse(
                self.run_task.done(),
                "run_until_shutdown_signal must wait for the in-flight forward",
            )

            self.blocking_forwarder.release.set()
            await asyncio.wait_for(self.run_task, timeout=5.0)

            result = await asyncio.wait_for(send_future, timeout=3.0)
            self.assertEqual(result[0], 250)

        audit_payloads = [
            json.loads(line.split("audit ", 1)[1]) for line in captured.output if "audit " in line
        ]
        self.assertTrue(
            any(payload["event"] == "smtp_message_forwarded" for payload in audit_payloads)
        )

    async def test_new_connection_during_shutdown_is_rejected(self):
        # Scenario B: while a forward from an earlier submission is
        # still draining, a brand-new SMTP connection must not be able
        # to start new forwarding work.
        loop = asyncio.get_running_loop()
        msg = _classroom_message()

        blocked_send = loop.run_in_executor(
            None, _submit_over_new_connection, self.server.port, msg, ["alice@example.com"]
        )
        started = await loop.run_in_executor(None, self.blocking_forwarder.started.wait, 2.0)
        self.assertTrue(started, "forward() never started")

        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.sleep(0.2)

        new_msg = _classroom_message(to="bob@example.com")
        new_result = await loop.run_in_executor(
            None, _submit_over_new_connection, self.server.port, new_msg, ["bob@example.com"]
        )
        self.assertEqual(new_result[0], 451)
        self.assertIn("shutting down", new_result[1].lower())

        self.blocking_forwarder.release.set()
        await asyncio.wait_for(self.run_task, timeout=5.0)
        await asyncio.wait_for(blocked_send, timeout=3.0)
        # Only the original, already-in-flight submission ever reached
        # the real forwarder -- the new connection's attempt during
        # shutdown never did, however long we wait.
        self.assertEqual(self.blocking_forwarder.inner.calls, 1)

    async def test_existing_session_cannot_submit_during_shutdown(self):
        # Scenario C: a session established *before* shutdown began
        # (already past EHLO/MAIL/RCPT) must not be able to start an
        # untracked forwarding operation by sending DATA *during*
        # shutdown.
        loop = asyncio.get_running_loop()
        msg = _classroom_message()

        blocked_send = loop.run_in_executor(
            None, _submit_over_new_connection, self.server.port, msg, ["alice@example.com"]
        )
        started = await loop.run_in_executor(None, self.blocking_forwarder.started.wait, 2.0)
        self.assertTrue(started, "forward() never started")

        existing_session = await loop.run_in_executor(
            None, _OpenSmtpSession, self.server.port
        )

        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.sleep(0.2)

        result = await loop.run_in_executor(
            None, existing_session.send_data, _classroom_message(to="carol@example.com")
        )
        self.assertEqual(result[0], 451)
        self.assertIn("shutting down", result[1].lower())
        existing_session.close()

        self.blocking_forwarder.release.set()
        await asyncio.wait_for(self.run_task, timeout=5.0)
        await asyncio.wait_for(blocked_send, timeout=3.0)
        # Only the original, already-in-flight submission ever reached
        # the real forwarder -- the existing session's second message,
        # submitted during shutdown, never did.
        self.assertEqual(self.blocking_forwarder.inner.calls, 1)

    async def test_client_disconnect_during_shutdown_still_completes(self):
        # Scenario D: a submitting client that disconnects (without
        # reading the response) while its forward is still blocked,
        # combined with a shutdown beginning at the same time, must
        # not fare any worse than either condition alone -- the
        # shielded task survives both the disconnect (already covered
        # elsewhere) and the shutdown drain (this round's fix), and
        # still records its real outcome.
        loop = asyncio.get_running_loop()
        msg = _classroom_message()

        with self.assertLogs("sl_smtp_proxy.smtp_server", level="INFO") as captured:
            disconnecting_send = loop.run_in_executor(
                None,
                submit_message_and_disconnect,
                self.server.port,
                msg,
                ["alice@example.com"],
            )
            started = await loop.run_in_executor(
                None, self.blocking_forwarder.started.wait, 2.0
            )
            self.assertTrue(started, "forward() never started")
            await asyncio.wait_for(disconnecting_send, timeout=3.0)

            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.sleep(0.2)
            self.assertFalse(
                self.run_task.done(),
                "run_until_shutdown_signal must wait for the in-flight forward",
            )

            self.blocking_forwarder.release.set()
            await asyncio.wait_for(self.run_task, timeout=5.0)

            def _forwarded_logged():
                return any(
                    '"event":"smtp_message_forwarded"' in line for line in captured.output
                )

            self.assertTrue(
                await _wait_until_async(_forwarded_logged, timeout=2.0),
                "expected a definitive smtp_message_forwarded audit event",
            )

        self.assertEqual(self.blocking_forwarder.inner.calls, 1)


if __name__ == "__main__":
    unittest.main()
