from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from email import policy
from email.message import Message
import hmac
import logging
import socket
import ssl
import time
import warnings
from typing import Dict, Optional, Sequence

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword, SMTP
from alias_routing_core import normalize_email_address
from simplelogin_client import RequestStats

from .cache import ReservationResult, SQLiteAliasCache
from .config import SmtpProxyConfig
from .config_validation import validate_startup_config
from .forwarder import (
    ForwardResult,
    UpstreamForwardingError,
    UpstreamSmtpForwarder,
    safe_forwarding_error_fields,
)
from .logging import audit_event, plan_audit_fields, plan_summary, redact_address, safe_reason
from .message_transform import (
    apply_transform,
    build_plan_for_message,
    parse_message,
    transformed_envelope_recipients,
)
from .mime_sender_validation import validate_mime_sender
from .reverse_alias_resolver import ResolutionStats, ReverseAliasResolver, resolver_from_config
from .safety_verifier import verify_post_transform_safety, visible_recipient_count


LOGGER = logging.getLogger(__name__)


def _new_correlation_id() -> str:
    return uuid.uuid4().hex[:12]


def _forward_fingerprint(sender: str, recipients: Sequence[str], message: Message) -> str:
    """Fingerprint a forwarded message for duplicate-submission suppression.

    Combines the message's own Message-Id (set once by the originating
    MUA and normally preserved across a client-side retry of the same
    compose) with a hash of the full serialized message, rather than
    relying on Message-Id alone: a client-side "edit and resend" that
    reuses the same Message-Id, or two separately imported messages that
    happen to share one, can otherwise have identical sender/recipients/
    Message-Id while their actual content differs, which would wrongly
    fingerprint them as the same message -- reporting the second as
    "already accepted for delivery" and silently never forwarding it.
    Including the content hash even when Message-Id is present ensures
    only byte-equivalent submissions are ever suppressed. This remains a
    best-effort defense, not a delivery guarantee: a client that
    generates a new Message-Id *and* content per retry will not be
    caught by it.
    """
    message_id = (message.get("Message-Id") or "").strip()
    content_hash = hashlib.sha256(message.as_bytes(policy=policy.SMTP)).hexdigest()
    normalized_sender = normalize_email_address(sender) or (sender or "").casefold()
    normalized_recipients = sorted(
        normalize_email_address(recipient) or recipient.casefold() for recipient in recipients
    )
    raw = "|".join([normalized_sender, ",".join(normalized_recipients), message_id, content_hash])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


_SHUTTING_DOWN_RESPONSE = (
    "451 SimpleLogin SMTP proxy is shutting down; please retry this message later"
)
_AT_CAPACITY_RESPONSE = (
    "451 SimpleLogin SMTP proxy is at capacity; please retry this message later"
)


class _CapacitySlot:
    """Owns exactly one max_concurrent_submissions slot and guarantees
    it is released exactly once, by whichever of two different owners
    actually ends up holding it last.

    A client disconnect cancels handle_DATA's own await, but (by
    design, via asyncio.shield) does not cancel the shielded
    _claim_duplicate_and_forward task -- that task keeps running, still
    holding the full transformed message in memory, until it finishes
    on its own. If the slot were released whenever handle_DATA's own
    coroutine exits -- including by cancellation -- a client could
    submit a unique message and disconnect immediately, over and over,
    freeing the slot again within milliseconds each time while the
    actual background work keeps piling up unbounded: the exact
    resource-exhaustion path max_concurrent_submissions exists to
    close. transfer_to_task() moves ownership to the task itself before
    it is ever awaited, so the slot stays held for as long as that
    task is genuinely still running, however long handle_DATA's own
    processing already took or however it ends.
    """

    __slots__ = ("_handler", "_transferred")

    def __init__(self, handler: "SmtpProxyHandler"):
        self._handler = handler
        self._transferred = False

    def transfer_to_task(self, task: "asyncio.Task") -> None:
        self._transferred = True
        task.add_done_callback(self._release)

    def release_if_not_transferred(self) -> None:
        if not self._transferred:
            self._handler._in_flight_submissions -= 1

    def _release(self, _task: "asyncio.Task" = None) -> None:
        self._handler._in_flight_submissions -= 1


def _swallow_task_exception(task: "asyncio.Task") -> None:
    # Safety net for the shielded forwarding task: if the client
    # disconnects, handle_DATA stops awaiting this task (though it keeps
    # running independently), so nothing else is guaranteed to retrieve
    # its result. Without this, asyncio logs "Task exception was never
    # retrieved" once the task is garbage collected. The real audit
    # logging for the outcome always happens inside the task itself.
    if task.cancelled():
        return
    task.exception()
TLS_MODES = {"starttls", "implicit"}
AIOSMTPD_AUTH_TLS_WARNING = (
    "Requiring AUTH while not requiring TLS can lead to security vulnerabilities!"
)
AIOSMTPD_AUTH_TLS_LOG_WARNING = "auth_required == True but auth_require_tls == False"


class _SmtpProxyController(Controller):
    def __init__(self, *args, suppress_auth_tls_warning: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self._suppress_auth_tls_warning = suppress_auth_tls_warning

    def factory(self):
        if not self._suppress_auth_tls_warning:
            return SMTP(self.handler, **self.SMTP_kwargs)

        with _suppress_aiosmtpd_auth_tls_warning():
            return SMTP(self.handler, **self.SMTP_kwargs)


class _AiosmtpdAuthTlsWarningFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.getMessage() != AIOSMTPD_AUTH_TLS_LOG_WARNING


@contextmanager
def _suppress_aiosmtpd_auth_tls_warning():
    mail_logger = logging.getLogger("mail.log")
    log_filter = _AiosmtpdAuthTlsWarningFilter()
    mail_logger.addFilter(log_filter)
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=AIOSMTPD_AUTH_TLS_WARNING,
                category=UserWarning,
                module="aiosmtpd.smtp",
            )
            yield
    finally:
        mail_logger.removeFilter(log_filter)


class SmtpProxyHandler:
    def __init__(self, config: SmtpProxyConfig, reverse_alias_resolver=None, forwarder=None):
        self.config = config
        self.last_plan = None
        self.reverse_alias_resolver = (
            reverse_alias_resolver
            if reverse_alias_resolver is not None
            else resolver_from_config(config)
        )
        self.forwarder = forwarder or UpstreamSmtpForwarder(config)
        self._dedup_cache = SQLiteAliasCache(config.cache_path)
        # Every shielded _claim_duplicate_and_forward task currently in
        # flight, tracked so a shutdown can wait for them -- see
        # drain_pending_forwards(). Only ever read or mutated from the
        # aiosmtpd controller's own event loop thread (where handle_DATA
        # and these tasks' done-callbacks run), never from the caller's
        # loop in SmtpProxyServer.stop().
        self._pending_forward_tasks: set = set()
        self._open_executors()

    def _open_executors(self) -> None:
        # Separate bounded pools for resolution (SimpleLogin API/cache work)
        # and forwarding (upstream SMTP) so a burst of large messages can't
        # spawn unbounded threads, and so one stage can't starve the other.
        self._resolver_executor = ThreadPoolExecutor(
            max_workers=max(1, self.config.resolver_max_workers),
            thread_name_prefix="sl-resolver",
        )
        self._forward_executor = ThreadPoolExecutor(
            max_workers=max(1, self.config.forward_max_workers),
            thread_name_prefix="sl-forward",
        )
        # The duplicate-suppression cache does synchronous SQLite writes
        # (reserve/renew/resolve). Each one is normally fast, but SQLite
        # can block a caller behind its own busy-timeout if the database
        # is locked by a concurrent writer (another connection's write, a
        # schema migration) -- running that wait on the event loop thread
        # would stall every other SMTP connection and health probe for as
        # long as the lock is held, defeating the whole point of the
        # bounded worker pools above. A small dedicated pool keeps this
        # off the event loop without contending with resolution/forwarding
        # for threads.
        self._dedup_executor = ThreadPoolExecutor(
            max_workers=4,
            thread_name_prefix="sl-dedup",
        )
        self._closed = False
        # Set by begin_shutdown() before draining, so no new message can
        # reach forwarding once a graceful shutdown has started -- see
        # that method and handle_DATA's check below. Reset here too so a
        # restarted server (reopen(), below) accepts new work again.
        # Like _pending_forward_tasks, only ever read or written from
        # the aiosmtpd controller's own event loop thread.
        self._shutting_down = False
        # How many submissions are currently inside handle_DATA (parsed,
        # resolving, transforming, or forwarding) -- see
        # config.max_concurrent_submissions. Reset here for the same
        # restart reason as _shutting_down above.
        self._in_flight_submissions = 0

    def reopen(self) -> None:
        """Recreate the worker pools if a previous close() shut them down.

        SmtpProxyServer.stop() calls close() but keeps the same handler
        instance, so a subsequent start() must be able to hand it fresh,
        usable executors rather than leaving handle_DATA to schedule work
        on pools that were already shut down.
        """
        if self._closed:
            self._open_executors()

    def close(self) -> None:
        self._resolver_executor.shutdown(wait=False)
        self._forward_executor.shutdown(wait=False)
        self._dedup_executor.shutdown(wait=False)
        self._closed = True

    async def begin_shutdown(self, controller_loop: asyncio.AbstractEventLoop) -> None:
        """Stop accepting new forwarding work, before anything is drained.

        Must complete -- and therefore must run on controller_loop,
        strictly before drain_pending_forwards's snapshot runs there --
        or a new submission could still reach handle_DATA's forwarding
        stage in the gap between starting the drain and actually
        stopping the controller, creating an untracked task the drain's
        snapshot never saw. Bridged via run_coroutine_threadsafe/
        wrap_future for the same cross-thread reason as
        drain_pending_forwards; see SmtpProxyServer.stop() for the
        required ordering of the two calls.

        Once this returns, every handle_DATA invocation still in
        flight -- for a brand-new connection that raced in, or an
        already-established session sending a second message -- sees
        _shutting_down and answers with a temporary rejection instead
        of creating a forwarding task, however far along it already is
        in resolution/transform.
        """

        async def _set_flag():
            self._shutting_down = True

        future = asyncio.run_coroutine_threadsafe(_set_flag(), controller_loop)
        await asyncio.wrap_future(future)

    async def drain_pending_forwards(self, controller_loop: asyncio.AbstractEventLoop) -> None:
        """Best-effort wait for in-flight shielded forwards before shutdown.

        Every _claim_duplicate_and_forward task runs shielded so a
        *client* disconnect never abandons it -- but stopping the proxy
        itself is a different story: aiosmtpd's Controller.stop() cancels
        every task on its own event loop directly (not through
        handle_DATA's await, which shield only protects against), so an
        in-flight task would otherwise be cut off mid-forward with no
        chance to record its outcome, even though the underlying worker
        thread keeps running and may still deliver the message upstream.
        That would leave the reservation stuck 'pending' until it is
        eventually reclaimed by age, allowing a future retry to resend a
        message that was already silently delivered -- the exact
        failure mode Goal C was meant to close, just at shutdown instead
        of client-disconnect time.

        Must run on controller_loop, not the caller's own loop: aiosmtpd
        runs its event loop in a dedicated background thread, so these
        tasks belong to a different loop than whatever loop
        SmtpProxyServer.stop() happens to be awaited from. Bridged via
        run_coroutine_threadsafe/wrap_future; the set itself is only
        ever touched from controller_loop's thread (see the attribute's
        docstring), so reading it inside the scheduled coroutine -- not
        here -- avoids a cross-thread race on a plain set.
        """
        drain_timeout = self.config.upstream_timeout_seconds + 5

        async def _wait_for_pending():
            pending = list(self._pending_forward_tasks)
            if not pending:
                return set(), set()
            return await asyncio.wait(pending, timeout=drain_timeout)

        concurrent_future = asyncio.run_coroutine_threadsafe(_wait_for_pending(), controller_loop)
        _done, still_pending = await asyncio.wrap_future(concurrent_future)
        if still_pending:
            LOGGER.warning(
                "%d shielded forwarding task(s) did not finish within %ss during "
                "shutdown; their delivery outcome may be lost if the upstream "
                "server had not already accepted them",
                len(still_pending),
                drain_timeout,
            )

    def _reject_for_shutdown(self, peer: str, correlation_id: str) -> str:
        LOGGER.info(
            "audit %s",
            audit_event(
                "smtp_message_rejected",
                peer=peer,
                correlation_id=correlation_id,
                policy="server_shutting_down",
                reason="SimpleLogin SMTP proxy is shutting down",
            ),
        )
        return _SHUTTING_DOWN_RESPONSE

    def _reject_for_capacity(self, peer: str, correlation_id: str) -> str:
        LOGGER.info(
            "audit %s",
            audit_event(
                "smtp_message_rejected",
                peer=peer,
                correlation_id=correlation_id,
                policy="at_capacity",
                reason="SimpleLogin SMTP proxy is at capacity",
                in_flight_submissions=self._in_flight_submissions,
            ),
        )
        return _AT_CAPACITY_RESPONSE

    async def handle_MAIL(self, server, session, envelope, address, mail_options) -> str:
        if not _sender_allowed(self.config, address):
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_sender_rejected",
                    peer=_peer_host(session),
                    sender=redact_address(address),
                    reason="sender_not_allowed",
                ),
            )
            return "550 Sender address is not allowed by SimpleLogin proxy policy"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope) -> str:
        correlation_id = _new_correlation_id()
        peer = _peer_host(session)
        if self._shutting_down:
            # Cheap early exit: avoids wasted SimpleLogin API calls for a
            # submission that will be rejected anyway. Not itself the
            # race-closing check -- see the one immediately before
            # creating the forwarding task below, which is what actually
            # guarantees no untracked task is created once a shutdown's
            # drain has started.
            return self._reject_for_shutdown(peer, correlation_id)
        if self._in_flight_submissions >= self.config.max_concurrent_submissions:
            # Rejected before any parsing/resolution work, not merely
            # queued behind it: resolver_max_workers/forward_max_workers
            # only bound how many worker threads are *actively* running,
            # not how many submissions can be waiting for one while each
            # holds its own (up to max_message_bytes) parsed/transformed
            # message in memory on the event loop. Without this cap, a
            # client opening enough concurrent sessions and sending
            # near-max-size messages while workers are busy (e.g. with
            # many uncached recipients) could grow memory usage without
            # bound.
            return self._reject_for_capacity(peer, correlation_id)
        self._in_flight_submissions += 1
        slot = _CapacitySlot(self)
        try:
            return await self._process_data(correlation_id, peer, envelope, slot)
        finally:
            # No-op if the submission reached the shielded forwarding
            # task below: that task owns the slot from then on,
            # regardless of whether (or how) this await itself ends --
            # see _CapacitySlot's docstring.
            slot.release_if_not_transferred()

    async def _process_data(
        self, correlation_id: str, peer: str, envelope, slot: "_CapacitySlot"
    ) -> str:
        loop = asyncio.get_running_loop()
        started = time.monotonic()
        phase = "parsing"
        timings: Dict[str, int] = {}
        request_stats = RequestStats()
        resolution_stats = ResolutionStats()
        try:
            content = envelope.original_content
            if content is None:
                content = envelope.content
            if isinstance(content, str):
                data = content.encode("utf-8", errors="replace")
            else:
                data = bytes(content or b"")

            parsed_message = parse_message(data)
            mime_sender_validation = validate_mime_sender(parsed_message, self.config)
            if not mime_sender_validation.accepted:
                LOGGER.info(
                    "audit %s",
                    audit_event(
                        "smtp_mime_sender_rejected",
                        peer=peer,
                        correlation_id=correlation_id,
                        policy="mime_sender_validation",
                        header=mime_sender_validation.header,
                        reason=mime_sender_validation.reason,
                        from_count=mime_sender_validation.from_count,
                        sender_count=mime_sender_validation.sender_count,
                    ),
                )
                return "550 MIME sender address is not allowed by SimpleLogin proxy policy"

            phase = "alias_refresh"
            alias_refresh_started = time.monotonic()
            extra_simplelogin_aliases = set()
            if self.config.strip_own_aliases and hasattr(self.reverse_alias_resolver, "owned_alias_emails"):
                # Only our own ReverseAliasResolver's owned_alias_emails()
                # understands request_stats; an injected/duck-typed
                # resolver (as used in tests and custom deployments) keeps
                # its original no-argument contract.
                if isinstance(self.reverse_alias_resolver, ReverseAliasResolver):
                    owned_alias_call = functools.partial(
                        self.reverse_alias_resolver.owned_alias_emails,
                        request_stats=request_stats,
                    )
                else:
                    owned_alias_call = self.reverse_alias_resolver.owned_alias_emails
                try:
                    extra_simplelogin_aliases = await loop.run_in_executor(
                        self._resolver_executor,
                        owned_alias_call,
                    )
                except Exception as exc:
                    public_message = getattr(exc, "public_message", type(exc).__name__)
                    LOGGER.info(
                        "audit %s",
                        audit_event(
                            "smtp_message_rejected",
                            peer=peer,
                            correlation_id=correlation_id,
                            policy="alias_refresh_failed",
                            reason=safe_reason(f"SimpleLogin alias refresh failed: {public_message}"),
                        ),
                    )
                    return f"550 SimpleLogin alias refresh failed: {public_message}"
            timings["alias_refresh_ms"] = int((time.monotonic() - alias_refresh_started) * 1000)

            # Recipient resolution runs in a worker thread: it can make
            # many blocking SimpleLogin HTTP requests for a bulk send, and
            # must never block the event loop (and therefore health
            # checks and other connections) while it does.
            phase = "resolution"
            resolution_started = time.monotonic()
            message, plan = await loop.run_in_executor(
                self._resolver_executor,
                functools.partial(
                    build_plan_for_message,
                    envelope.mail_from or "",
                    list(envelope.rcpt_tos),
                    data,
                    self.config,
                    reverse_alias_resolver=self.reverse_alias_resolver,
                    extra_simplelogin_aliases=extra_simplelogin_aliases,
                    request_stats=request_stats,
                    resolution_stats=resolution_stats,
                ),
            )
            timings["resolution_ms"] = int((time.monotonic() - resolution_started) * 1000)
            self.last_plan = plan
            LOGGER.info("transform_plan %s", plan_summary(plan, self.config.log_redact_addresses))
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_transform_plan",
                    peer=peer,
                    correlation_id=correlation_id,
                    simplelogin_request_count=request_stats.request_count,
                    simplelogin_request_duration_ms=int(request_stats.total_duration_seconds * 1000),
                    cache_hit_count=resolution_stats.cache_hits,
                    cache_miss_count=resolution_stats.cache_misses,
                    contacts_found=resolution_stats.contacts_found,
                    contacts_created=resolution_stats.contacts_created,
                    **timings,
                    **plan_audit_fields(plan, self.config.log_redact_addresses),
                ),
            )
            if plan.rejected:
                LOGGER.info(
                    "audit %s",
                    audit_event(
                        "smtp_message_rejected",
                        peer=peer,
                        correlation_id=correlation_id,
                        policy="transform_plan_rejected",
                        reason=safe_reason(plan.rejection_reason),
                    ),
                )
                return f"550 {plan.rejection_reason or 'Message rejected by SimpleLogin proxy policy'}"

            phase = "transform"
            transform_started = time.monotonic()
            transformed_message = apply_transform(message, plan, self.config)
            transformed_recipients = transformed_envelope_recipients(plan)
            verification = verify_post_transform_safety(
                transformed_message,
                transformed_recipients,
                self.config,
                plan,
                extra_simplelogin_aliases=extra_simplelogin_aliases,
            )
            timings["transform_validate_ms"] = int((time.monotonic() - transform_started) * 1000)
            if not verification.accepted:
                LOGGER.info(
                    "audit %s",
                    audit_event(
                        "smtp_message_rejected",
                        peer=peer,
                        correlation_id=correlation_id,
                        policy="post_transform_safety_verifier",
                        invariant=verification.invariant,
                        location=verification.location,
                        reason=verification.reason,
                        recipient_count=len(transformed_recipients),
                        visible_recipient_count=visible_recipient_count(transformed_message),
                    ),
                )
                return "550 Message rejected by SimpleLogin proxy post-transform safety verifier"
            if not transformed_recipients:
                LOGGER.info(
                    "audit %s",
                    audit_event(
                        "smtp_message_rejected",
                        peer=peer,
                        correlation_id=correlation_id,
                        policy="no_deliverable_recipients",
                        reason="No deliverable recipients after SimpleLogin routing",
                    ),
                )
                return "550 No deliverable recipients after SimpleLogin routing"
            if self.config.dry_run:
                LOGGER.info(
                    "audit %s",
                    audit_event(
                        "smtp_message_rejected",
                        peer=peer,
                        correlation_id=correlation_id,
                        policy="dry_run",
                        reason="SimpleLogin SMTP proxy dry-run: message not forwarded",
                    ),
                )
                return "550 SimpleLogin SMTP proxy dry-run: message not forwarded"

            # From here on, computing the fingerprint, claiming the
            # duplicate-reservation, and (if claimed) actually forwarding
            # all run as a single independent, shielded task: if the
            # client disconnects while this is in flight, handle_DATA's
            # own await is cancelled (as it must be, so the connection
            # teardown proceeds normally), but the task keeps running to
            # completion and always logs its real outcome. This must
            # cover the fingerprint computation and the reservation claim
            # too, not just the network forward -- both are themselves
            # off-event-loop work (see _dedup_executor below), so without
            # this, a disconnect landing in either of those narrow
            # windows could abandon a message before a reservation was
            # even attempted, or leave a 'pending' reservation that
            # nothing would ever resolve, and a message that was never
            # forwarded and never retried until its lease and
            # abandoned-grace period both elapsed. An upstream send
            # already accepted by Proton Bridge is, as before, never
            # silently dropped on the floor just because nobody is left
            # to read the SMTP response.
            #
            # The _shutting_down check right here -- immediately before
            # creating the task, with no await in between -- is what
            # actually closes the shutdown-drain race: begin_shutdown()
            # and this check both run on this same event loop, so this
            # check-then-create sequence can never straddle the moment
            # the flag flips. Either this task is created and registered
            # before begin_shutdown()'s flag flip (in which case
            # drain_pending_forwards's later snapshot is guaranteed to
            # include it), or this check already sees the flag set and
            # no task is created at all -- there is no window where a
            # task could be created *after* the flag flips but *before*
            # the drain's snapshot, which is exactly the race Codex's
            # review flagged against the first version of this fix.
            if self._shutting_down:
                return self._reject_for_shutdown(peer, correlation_id)
            phase = "forwarding"
            forward_started = time.monotonic()
            outcome_task = asyncio.ensure_future(
                self._claim_duplicate_and_forward(
                    correlation_id=correlation_id,
                    peer=peer,
                    sender=envelope.mail_from or "",
                    recipients=transformed_recipients,
                    message=transformed_message,
                    started=forward_started,
                )
            )
            self._pending_forward_tasks.add(outcome_task)
            outcome_task.add_done_callback(self._pending_forward_tasks.discard)
            outcome_task.add_done_callback(_swallow_task_exception)
            # From here on, the capacity slot belongs to outcome_task,
            # not to this coroutine: a client disconnect cancels only
            # the await below, never the shielded task itself, and the
            # slot must stay held for as long as that task is actually
            # still running -- see _CapacitySlot's docstring.
            slot.transfer_to_task(outcome_task)
            try:
                return await asyncio.shield(outcome_task)
            except UpstreamForwardingError as exc:
                if exc.ambiguous_delivery:
                    # The connection to upstream was lost or timed out
                    # while the message was already being transmitted: it
                    # may have been accepted despite this error. Do not
                    # tell the client it was definitively rejected.
                    return (
                        "451 Upstream SMTP connection lost before a delivery confirmation "
                        "was received; please retry"
                    )
                return f"550 {exc.public_message}"
            except Exception:
                return "451 SimpleLogin SMTP proxy internal error while forwarding"
        except asyncio.CancelledError:
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_client_disconnected_during_processing",
                    peer=peer,
                    correlation_id=correlation_id,
                    phase=phase,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                ),
            )
            raise

    def _dedup_prune_window_seconds(self) -> int:
        # Pruning must never remove a row that is still meaningful: either
        # still within the duplicate-suppression window, or still needed
        # to detect an in-flight/abandoned reservation.
        return max(
            self.config.duplicate_suppression_window_seconds,
            self.config.duplicate_reservation_lease_seconds
            + self.config.duplicate_reservation_abandoned_grace_seconds,
        )

    async def _claim_duplicate_and_forward(
        self,
        correlation_id: str,
        peer: str,
        sender: str,
        recipients,
        message: Message,
        started: float,
    ) -> str:
        """Compute the fingerprint and claim the duplicate-suppression
        reservation, if enabled, then dispatch to actual forwarding if
        and only if it was claimed.

        Called as a single shielded task from handle_DATA so that a
        client disconnect can never land in between "fingerprint
        computed", "reservation claimed", and "forwarding started" --
        see the comment at that call site.
        """
        loop = asyncio.get_running_loop()
        fingerprint: Optional[str] = None
        if self.config.duplicate_suppression_window_seconds > 0:
            # Serializing the full (possibly near-max_message_bytes)
            # message and hashing it is real, synchronous CPU work --
            # run it off the event loop like every other blocking
            # submission stage, not inline, or a large message (or
            # several concurrent ones) stalls every other connection
            # and health probe for as long as it takes.
            fingerprint = await loop.run_in_executor(
                self._dedup_executor,
                functools.partial(_forward_fingerprint, sender, recipients, message),
            )

        if fingerprint:
            try:
                # Atomically claim the fingerprint here, before forwarding,
                # rather than just checking it: a client that disconnects
                # during a slow upstream send and immediately retries would
                # otherwise have both submissions pass a read-only check
                # before either one records success, and both would forward.
                # Run on the dedup executor, not the event loop directly:
                # if the SQLite file is locked by a concurrent writer, this
                # write can block for up to SQLite's busy timeout, which
                # must never stall other connections/health checks.
                reservation = await loop.run_in_executor(
                    self._dedup_executor,
                    functools.partial(
                        self._dedup_cache.try_reserve_forwarding,
                        fingerprint,
                        correlation_id,
                        self.config.duplicate_suppression_window_seconds,
                        self.config.duplicate_reservation_lease_seconds,
                        self.config.duplicate_reservation_abandoned_grace_seconds,
                    ),
                )
            except Exception:
                # Duplicate suppression is a best-effort safety net, not a
                # delivery gate: a local cache/disk problem must not block
                # legitimate mail. Fail open here and still try to forward
                # normally.
                LOGGER.exception("Duplicate-submission cache lookup failed; forwarding anyway")
                reservation = ReservationResult(outcome="claimed")

            if reservation.outcome == "completed":
                # The upstream SMTP server already accepted this exact
                # message within the suppression window. Report the
                # already-known success rather than forwarding (and
                # therefore delivering) it a second time.
                LOGGER.info(
                    "audit %s",
                    audit_event(
                        "smtp_duplicate_already_delivered",
                        peer=peer,
                        correlation_id=correlation_id,
                        policy="duplicate_already_delivered",
                        prior_correlation_id=reservation.prior_attempt_id or "unknown",
                        recipient_count=len(recipients),
                    ),
                )
                return "250 Message already accepted for delivery"

            if reservation.outcome == "partial":
                # The upstream SMTP server already confirmed-accepted
                # some recipients and confirmed-refused the rest of this
                # exact message. The proxy cannot resend to only the
                # refused subset, so this must never be forwarded again
                # automatically: that would redeliver to the recipients
                # already accepted. Unlike "completed", this is reported
                # as a *permanent* failure (550), not a temporary one:
                # a 4xx response is a standing invitation for a
                # compliant SMTP client (or an intermediate MTA) to keep
                # retrying the identical message indefinitely, which
                # this fingerprint must never honor, at any age -- see
                # try_reserve_forwarding's "partial" outcome.
                LOGGER.info(
                    "audit %s",
                    audit_event(
                        "smtp_duplicate_partial_delivery",
                        peer=peer,
                        correlation_id=correlation_id,
                        policy="duplicate_partial_delivery",
                        prior_correlation_id=reservation.prior_attempt_id or "unknown",
                        recipient_count=len(recipients),
                    ),
                )
                return (
                    "550 A matching submission was already partially delivered to some "
                    "recipients and refused for others; it will not be forwarded again. "
                    "Contact your mail administrator to identify and resend to the "
                    "affected recipient(s) only."
                )

            if reservation.outcome in ("in_flight", "abandoned"):
                # A matching submission is either genuinely still being
                # forwarded ("in_flight") or its reservation lease expired
                # without being resolved, most likely because the proxy
                # process was killed mid-send ("abandoned"). Neither case
                # tells us the original message was never delivered, so
                # forwarding this one now could create a duplicate. Defer
                # with a temporary response instead of a permanent one: a
                # legitimate client should retry later rather than treat
                # this as a hard bounce.
                LOGGER.info(
                    "audit %s",
                    audit_event(
                        "smtp_message_deferred",
                        peer=peer,
                        correlation_id=correlation_id,
                        policy=(
                            "duplicate_in_flight"
                            if reservation.outcome == "in_flight"
                            else "duplicate_reservation_abandoned"
                        ),
                        prior_correlation_id=reservation.prior_attempt_id or "unknown",
                        reservation_age_ms=(
                            int(reservation.age_seconds * 1000)
                            if reservation.age_seconds is not None
                            else None
                        ),
                        recipient_count=len(recipients),
                    ),
                )
                return (
                    "451 A matching submission is already being processed or its "
                    "delivery outcome is not yet confirmed; please retry shortly"
                )

        result = await self._forward_and_record(
            correlation_id=correlation_id,
            peer=peer,
            sender=sender,
            recipients=recipients,
            message=message,
            fingerprint=fingerprint,
            started=started,
        )
        if result.refused_count:
            # Some recipients were confirmed-accepted and some were
            # confirmed-refused by the upstream server. A plain 250
            # would misreport this as complete success. A temporary
            # (4xx) response was considered instead of 550, to avoid
            # claiming the whole submission failed when most of it was
            # delivered -- but 4xx is an explicit invitation for a
            # compliant SMTP client or intermediate MTA to automatically
            # retry the identical message, and the dedup state machine's
            # "partial" outcome permanently refuses to re-forward this
            # fingerprint precisely because that retry must never
            # redeliver to the recipients already accepted. Reporting a
            # retryable code here would contradict that guarantee, so
            # this is a permanent failure (550): the submission, as
            # sent, will never succeed, and the client must not retry it
            # unmodified.
            return (
                f"550 Message delivered to {result.accepted_count} of "
                f"{result.total_count} recipient(s); {result.refused_count} "
                "recipient(s) were refused by the upstream mail server and did NOT "
                "receive this message. It will not be forwarded again. Contact your "
                "mail administrator to identify and resend to the affected "
                "recipient(s) only."
            )
        return "250 Message accepted for delivery"

    async def _renew_reservation_periodically(self, fingerprint: str, attempt_id: str) -> None:
        """Keep a pending reservation's lease alive while genuinely in
        progress, so a slow-but-alive forward is never mistaken for an
        abandoned (crashed) one just because it outlives the lease
        duration. Runs until cancelled by the forwarding attempt that
        started it, win or lose.
        """
        interval_seconds = max(0.1, self.config.duplicate_reservation_lease_seconds / 3)
        loop = asyncio.get_running_loop()
        try:
            while True:
                await asyncio.sleep(interval_seconds)
                try:
                    # Off the event loop, like every other dedup cache
                    # write -- see the comment on _dedup_executor.
                    await loop.run_in_executor(
                        self._dedup_executor,
                        self._dedup_cache.renew_reservation,
                        fingerprint,
                        attempt_id,
                    )
                except Exception:
                    LOGGER.exception("Failed to renew duplicate-suppression reservation lease")
        except asyncio.CancelledError:
            pass

    async def _forward_and_record(
        self,
        correlation_id: str,
        peer: str,
        sender: str,
        recipients,
        message: Message,
        fingerprint: Optional[str],
        started: float,
    ) -> ForwardResult:
        loop = asyncio.get_running_loop()
        renew_task = None
        if fingerprint:
            renew_task = asyncio.ensure_future(
                self._renew_reservation_periodically(fingerprint, correlation_id)
            )
        try:
            result = await loop.run_in_executor(
                self._forward_executor,
                self.forwarder.forward,
                sender,
                recipients,
                message,
            )
        except Exception as exc:
            forward_duration_ms = int((time.monotonic() - started) * 1000)
            # A confirmed failure is a definitive UpstreamForwardingError
            # raised before any message bytes were sent, or in response to
            # an explicit rejection reply -- nothing was delivered, so the
            # fingerprint is immediately eligible for a legitimate retry
            # to reclaim (see try_reserve_forwarding). Everything else --
            # an unexpected exception, or an UpstreamForwardingError
            # flagged ambiguous_delivery (the connection was lost or timed
            # out while the message bytes were already being transmitted,
            # so the upstream may have already accepted it) -- is treated
            # as outcome-unknown: deliberately leave the reservation
            # 'pending' rather than guess. A later resubmission's
            # try_reserve_forwarding call will see it as in-flight, then
            # abandoned once its lease expires, and only reclaim it
            # (accepting the documented residual duplicate risk) after the
            # abandoned-reservation grace period.
            confirmed_failure = isinstance(exc, UpstreamForwardingError) and not exc.ambiguous_delivery
            if fingerprint and confirmed_failure:
                try:
                    await loop.run_in_executor(
                        self._dedup_executor,
                        functools.partial(
                            self._dedup_cache.mark_failed,
                            fingerprint,
                            correlation_id,
                            prune_older_than_seconds=self._dedup_prune_window_seconds(),
                        ),
                    )
                except Exception:
                    LOGGER.exception("Failed to record forwarded-message dedup failure")

            if confirmed_failure:
                LOGGER.info(
                    "audit %s",
                    audit_event(
                        "smtp_message_rejected",
                        peer=peer,
                        correlation_id=correlation_id,
                        policy="upstream_unavailable",
                        reason=safe_reason(exc.public_message),
                        recipient_count=len(recipients),
                        forward_duration_ms=forward_duration_ms,
                    ),
                )
            else:
                # Every forwarding attempt must have an observable terminal
                # outcome, including unexpected or ambiguous failures: an
                # exception here must not disappear silently just because
                # the submitting client already disconnected and nobody is
                # left to read handle_DATA's return value.
                # error_type/error_category are structured and sanitized
                # (see safe_forwarding_error_fields) specifically so this
                # can never leak recipient addresses, message content, or
                # credentials embedded in exc's own message text. For an
                # ambiguous UpstreamForwardingError, classify the original
                # smtplib/OSError cause rather than the generic wrapper, so
                # the audit event still reports something specific like
                # "server_disconnected" instead of "unexpected".
                error_source = exc.__cause__ if isinstance(exc, UpstreamForwardingError) else exc
                LOGGER.info(
                    "audit %s",
                    audit_event(
                        "smtp_forwarding_outcome_unknown",
                        peer=peer,
                        correlation_id=correlation_id,
                        policy="internal_error",
                        recipient_count=len(recipients),
                        forward_duration_ms=forward_duration_ms,
                        **safe_forwarding_error_fields(error_source or exc),
                    ),
                )
            raise
        finally:
            if renew_task is not None:
                renew_task.cancel()
                try:
                    await renew_task
                except asyncio.CancelledError:
                    pass

        if result is None:
            # Backward compatibility: a custom forwarder injected via
            # SmtpProxyServer(forwarder=...) that still implements the
            # contract from before the eighth review round's partial-
            # acceptance fix returns nothing on success (raising only on
            # failure), not a ForwardResult. Treat that exactly as a
            # full, unqualified success. Without this, result.is_partial
            # below would raise AttributeError -- and since that would
            # happen *after* the forward already succeeded but *before*
            # mark_forwarded ever runs, the dedup reservation would be
            # left stuck 'pending' while the client is told to retry:
            # once the abandoned-reservation grace period elapsed, that
            # retry would silently redeliver an already-accepted
            # message a second time, the exact failure mode this whole
            # feature exists to prevent.
            result = ForwardResult(accepted_count=len(recipients), refused_count=0)

        forward_duration_ms = int((time.monotonic() - started) * 1000)
        if result.is_partial:
            # The upstream server confirmed-accepted some recipients and
            # confirmed-refused the rest (smtplib raises instead of
            # returning when *every* recipient is refused -- see
            # ForwardResult). Record this as its own terminal state,
            # distinct from both "completed" and "failed": the accepted
            # recipients already received the message, so the fingerprint
            # must never become eligible for an automatic full resend,
            # exactly like a completed send.
            if fingerprint:
                # Persisted on the row itself, never logged: this is the
                # only durable record of which recipient needs the
                # documented manual resend, since the permanent
                # "partial" dedup state means this exact submission can
                # never be replayed later to reproduce it, and a DEBUG
                # log line (see forwarder.py) only exists if an operator
                # happened to already be watching at this exact moment.
                detail = json.dumps(
                    {
                        "refused_recipients": list(result.refused_recipients),
                        "refused_smtp_codes": list(result.refused_smtp_codes),
                    },
                    sort_keys=True,
                )
                try:
                    await loop.run_in_executor(
                        self._dedup_executor,
                        functools.partial(
                            self._dedup_cache.mark_partial,
                            fingerprint,
                            correlation_id,
                            prune_older_than_seconds=self._dedup_prune_window_seconds(),
                            detail=detail,
                        ),
                    )
                except Exception:
                    LOGGER.exception("Failed to record forwarded-message dedup partial outcome")
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_message_partially_forwarded",
                    peer=peer,
                    correlation_id=correlation_id,
                    recipient_count=result.total_count,
                    accepted_count=result.accepted_count,
                    refused_count=result.refused_count,
                    refused_smtp_codes=list(result.refused_smtp_codes),
                    forward_duration_ms=forward_duration_ms,
                    duplicate_suppression_state="partial",
                ),
            )
            return result

        if fingerprint:
            try:
                await loop.run_in_executor(
                    self._dedup_executor,
                    functools.partial(
                        self._dedup_cache.mark_forwarded,
                        fingerprint,
                        correlation_id,
                        prune_older_than_seconds=self._dedup_prune_window_seconds(),
                    ),
                )
            except Exception:
                LOGGER.exception("Failed to record forwarded-message dedup fingerprint")
        LOGGER.info(
            "audit %s",
            audit_event(
                "smtp_message_forwarded",
                peer=peer,
                correlation_id=correlation_id,
                recipient_count=len(recipients),
                forward_duration_ms=forward_duration_ms,
            ),
        )
        return result

    def handle_exception(self, error: Exception) -> str:
        LOGGER.exception("SMTP proxy handler failed: %s", type(error).__name__)
        LOGGER.info(
            "audit %s",
            audit_event("smtp_internal_error", error_type=type(error).__name__),
        )
        return "451 SimpleLogin SMTP proxy internal error"


class SmtpProxyServer:
    def __init__(self, config: SmtpProxyConfig, reverse_alias_resolver=None, forwarder=None):
        self.config = config
        self.handler = SmtpProxyHandler(
            config,
            reverse_alias_resolver=reverse_alias_resolver,
            forwarder=forwarder,
        )
        self._controller: Optional[Controller] = None

    @property
    def last_plan(self):
        return self.handler.last_plan

    @property
    def port(self) -> int:
        if not self._controller or not self._controller.server:
            return self.config.port
        sockets = self._controller.server.sockets or []
        if not sockets:
            return self.config.port
        return int(sockets[0].getsockname()[1])

    async def start(self) -> None:
        validate_startup_config(self.config)
        self.handler.reopen()
        controller_ssl_context, smtp_tls_context, require_starttls, auth_require_tls = (
            _tls_settings(self.config)
        )

        self._controller = _SmtpProxyController(
            self.handler,
            hostname=self.config.host,
            port=_resolve_listen_port(self.config.host, self.config.port),
            ssl_context=controller_ssl_context,
            ready_timeout=5.0,
            server_hostname="simplelogin-smtp-proxy",
            tls_context=smtp_tls_context,
            require_starttls=require_starttls,
            data_size_limit=self.config.max_message_bytes,
            decode_data=False,
            auth_required=self.config.require_auth,
            auth_require_tls=auth_require_tls,
            authenticator=_authenticator(self.config) if self.config.require_auth else None,
            auth_exclude_mechanism=_excluded_auth_mechanisms(self.config),
            command_call_limit={"RCPT": 500, "NOOP": 20, "RSET": 20, "*": 100},
            suppress_auth_tls_warning=_suppress_auth_tls_warning(
                self.config,
                controller_ssl_context,
                smtp_tls_context,
                auth_require_tls,
            ),
        )
        self._controller.start()

    async def serve_forever(self) -> None:
        if not self._controller:
            await self.start()
        while True:
            await asyncio.sleep(3600)

    async def stop(self) -> None:
        if self._controller is not None:
            # Strict order matters here. begin_shutdown() must complete
            # before drain_pending_forwards() takes its snapshot. Without
            # that order, a new submission could still reach handle_DATA's
            # forwarding stage in the gap between starting the drain and
            # actually stopping the controller, creating a task the
            # drain's snapshot never saw -- the race Codex's review found
            # in the first version of this fix. And drain_pending_forwards
            # must in turn happen before controller.stop(): that call
            # cancels every task on the controller's own loop directly,
            # which would cut off an in-flight shielded forward before it
            # can record its outcome. See both methods' docstrings.
            await self.handler.begin_shutdown(self._controller.loop)
            await self.handler.drain_pending_forwards(self._controller.loop)
        self.handler.close()
        if not self._controller:
            return
        self._controller.stop(no_assert=True)
        self._controller = None


def _authenticator(config: SmtpProxyConfig):
    expected_username = config.username.encode("utf-8")
    expected_password = config.password.encode("utf-8")

    def authenticate(server, session, envelope, mechanism, auth_data) -> AuthResult:
        login = b""
        password = b""
        if isinstance(auth_data, LoginPassword):
            login = auth_data.login
            password = auth_data.password
        success = hmac.compare_digest(login, expected_username) and hmac.compare_digest(
            password,
            expected_password,
        )
        if success:
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_auth_succeeded",
                    mechanism=str(mechanism or "unknown"),
                    peer=_peer_host(session),
                ),
            )
            return AuthResult(success=True)

        delay_seconds = max(0.0, config.auth_failure_delay_seconds)
        LOGGER.info(
            "audit %s",
            audit_event(
                "smtp_auth_failed",
                delay_seconds=delay_seconds,
                mechanism=str(mechanism or "unknown"),
                peer=_peer_host(session),
            ),
        )
        if delay_seconds:
            time.sleep(delay_seconds)
        return AuthResult(
            success=False,
            handled=False,
            message="535 5.7.8 Authentication credentials invalid",
        )

    return authenticate


def _excluded_auth_mechanisms(config: SmtpProxyConfig):
    if config.auth_login_enabled:
        return []
    return ["LOGIN"]


def _sender_allowed(config: SmtpProxyConfig, sender: str) -> bool:
    if not config.user_mailboxes:
        return True

    normalized_sender = normalize_email_address(sender or "")
    if not normalized_sender:
        return False

    allowed = {
        normalized
        for normalized in (
            normalize_email_address(mailbox)
            for mailbox in config.user_mailboxes
        )
        if normalized
    }
    return normalized_sender in allowed


def _peer_host(session) -> str:
    peer = getattr(session, "peer", None)
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    if peer:
        return str(peer)
    return "unknown"


def _tls_settings(config: SmtpProxyConfig):
    tls_context = _tls_context(config)
    if tls_context is None:
        return None, None, False, False

    tls_mode = config.tls_mode.strip().lower()
    if tls_mode not in TLS_MODES:
        raise RuntimeError(
            "SMTP_PROXY_TLS_MODE must be 'starttls' or 'implicit'."
        )

    if tls_mode == "implicit":
        # aiosmtpd's auth_require_tls only recognizes STARTTLS upgrades. With
        # implicit TLS, the socket is encrypted before SMTP handling begins.
        return tls_context, None, False, False

    return None, tls_context, config.require_tls, True


def _tls_context(config: SmtpProxyConfig) -> Optional[ssl.SSLContext]:
    tls_requested = config.require_tls or bool(config.tls_cert_file or config.tls_key_file)
    if not tls_requested:
        return None

    if not config.tls_cert_file or not config.tls_key_file:
        raise RuntimeError(
            "SMTP proxy TLS requires both SMTP_PROXY_TLS_CERT_FILE and SMTP_PROXY_TLS_KEY_FILE."
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        certfile=config.tls_cert_file,
        keyfile=config.tls_key_file,
    )
    return context


def _suppress_auth_tls_warning(
    config: SmtpProxyConfig,
    controller_ssl_context: Optional[ssl.SSLContext],
    smtp_tls_context: Optional[ssl.SSLContext],
    auth_require_tls: bool,
) -> bool:
    return (
        config.require_auth
        and controller_ssl_context is not None
        and smtp_tls_context is None
        and not auth_require_tls
        and config.tls_mode.strip().lower() == "implicit"
    )


def _resolve_listen_port(host: str, port: int) -> int:
    if port != 0:
        return port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])
