from __future__ import annotations

import asyncio
import logging
import signal

from .config import load_config_from_env
from .logging import audit_event, configure_logging
from .smtp_server import SmtpProxyServer

LOGGER = logging.getLogger(__name__)


async def run_until_shutdown_signal(server: SmtpProxyServer) -> None:
    """Keep the server running until SIGTERM/SIGINT, then stop() it.

    Equivalent to server.serve_forever() in that it blocks for as long
    as the server should keep accepting mail, except it returns once
    asked to shut down -- and only after server.stop() has completed --
    rather than blocking forever. That lets Docker's SIGTERM (sent on
    `docker stop`/`docker compose down`, or when a container is
    replaced during a rolling restart) trigger an orderly shutdown
    instead of the process just being killed with in-flight forwards
    (already accepted by Proton Bridge, in the original incident this
    whole feature exists to prevent a recurrence of) abandoned
    mid-send.
    """
    loop = asyncio.get_running_loop()
    shutdown_requested = asyncio.Event()

    def _handle_signal(sig: signal.Signals) -> None:
        # Deliberately idempotent: a second signal while shutdown is
        # already under way (an impatient double Ctrl-C, or SIGTERM
        # followed eventually by Docker's own SIGKILL once
        # stop_grace_period elapses) just re-sets an already-set
        # Event. Nothing re-awaits shutdown_requested after the single
        # wait() below returns, so this can never trigger a second,
        # concurrent call to server.stop().
        LOGGER.info(
            "audit %s",
            audit_event("smtp_proxy_shutdown_signal_received", signal=sig.name),
        )
        shutdown_requested.set()

    registered_signals = []
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _handle_signal, sig)
        except (NotImplementedError, RuntimeError):
            # add_signal_handler is POSIX-only and must run on the main
            # thread of the main interpreter; outside that (e.g.
            # Windows, or an event loop running on a worker thread)
            # fall back to the plain serve_forever() wait below -- an
            # operator in that environment relies on the process being
            # terminated outright, exactly as before this change.
            continue
        registered_signals.append(sig)

    try:
        if not registered_signals:
            await server.serve_forever()
            return
        await shutdown_requested.wait()

        # Handlers stay installed through the whole drain-then-stop
        # sequence below, not just the wait above: removing them any
        # earlier would mean a second SIGTERM/SIGINT arriving while
        # server.stop() is still draining an in-flight forward (an
        # impatient double Ctrl-C, or a monitoring tool re-sending
        # SIGTERM) falls through to the process's default disposition
        # instead -- SIGTERM would kill the process immediately, and
        # SIGINT would raise KeyboardInterrupt out of asyncio.run --
        # defeating the whole point of this function and leaving the
        # reservation 'pending' even though the upstream worker thread
        # might still go on to deliver the message. _handle_signal
        # already documents that a repeat signal while shutting down is
        # meant to be a harmless no-op; that is only true while the
        # handler is still registered to catch it.
        LOGGER.info("audit %s", audit_event("smtp_proxy_shutdown_started"))
        try:
            await server.stop()
        except Exception:
            # Shutting down itself failing must not look like an
            # ordinary per-message processing error (handle_exception's
            # smtp_internal_error), and must not prevent the process
            # from exiting -- Docker (or systemd) forcibly terminates it
            # once stop_grace_period elapses regardless of what happens
            # here.
            LOGGER.exception("Error while shutting down SimpleLogin SMTP proxy")
        else:
            LOGGER.info("audit %s", audit_event("smtp_proxy_shutdown_completed"))
    finally:
        for sig in registered_signals:
            loop.remove_signal_handler(sig)


async def main() -> None:
    config = load_config_from_env()
    configure_logging(config.log_level, config.aiosmtpd_log_level)
    server = SmtpProxyServer(config)
    await server.start()
    LOGGER.info(
        "SimpleLogin SMTP proxy listening on %s:%s dry_run=%s",
        config.host,
        server.port,
        config.dry_run,
    )
    await run_until_shutdown_signal(server)


def cli() -> None:
    asyncio.run(main())


if __name__ == "__main__":
    cli()
