from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, Optional, Tuple, Union
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .config import (
    SecretFileError,
    SmtpProxyConfig,
    env_bool,
    env_float,
    env_int,
    env_secret,
    load_config_from_env,
)


DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_HISTORY_PATH = "/data/healthcheck.jsonl"
DEFAULT_STATE_PATH = "/data/healthcheck-state.json"
DEFAULT_HISTORY_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_ALERT_AFTER_FAILURES = 3
PUSHOVER_API_URL = "https://api.pushover.net/1/messages.json"


class HealthcheckError(RuntimeError):
    pass


@dataclass
class HealthcheckSettings:
    history_path: str = DEFAULT_HISTORY_PATH
    history_max_bytes: int = DEFAULT_HISTORY_MAX_BYTES
    state_path: str = DEFAULT_STATE_PATH
    alert_after_failures: int = DEFAULT_ALERT_AFTER_FAILURES
    pushover_enabled: bool = False
    pushover_app_token: str = ""
    pushover_user_key: str = ""
    pushover_device: str = ""
    pushover_priority: int = 0
    pushover_title: str = "SimpleLogin SMTP proxy"
    pushover_timeout_seconds: float = 5.0
    pushover_recovery_enabled: bool = True
    pushover_config_error: str = ""


def check_health(
    config: SmtpProxyConfig,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> None:
    host = _connect_host(config.host)
    with socket.create_connection((host, config.port), timeout=timeout_seconds) as raw_sock:
        raw_sock.settimeout(timeout_seconds)
        sock = _wrap_implicit_tls_if_needed(raw_sock, config, host)
        try:
            sock.settimeout(timeout_seconds)
            banner = _readline(sock)
            if not banner.startswith(b"220"):
                raise HealthcheckError("SMTP proxy did not return a ready banner")
            try:
                sock.sendall(b"QUIT\r\n")
            except OSError:
                pass
        finally:
            if sock is not raw_sock:
                sock.close()


def main() -> int:
    config = load_config_from_env()
    settings = load_healthcheck_settings_from_env()
    timeout_seconds = float(os.environ.get("SMTP_PROXY_HEALTHCHECK_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS))
    started = time.monotonic()
    try:
        check_health(config, timeout_seconds=timeout_seconds)
    except Exception as exc:
        message = f"healthcheck failed: {type(exc).__name__}: {exc}"
        record_healthcheck_result(
            settings,
            {
                "timestamp": utc_timestamp(),
                "status": "failed",
                "exit_code": 1,
                "duration_ms": elapsed_ms(started),
                "message": message,
                "error_type": type(exc).__name__,
                "host": config.host,
                "port": config.port,
            },
        )
        print(message, file=sys.stderr)
        return 1

    message = "healthcheck ok"
    record_healthcheck_result(
        settings,
        {
            "timestamp": utc_timestamp(),
            "status": "ok",
            "exit_code": 0,
            "duration_ms": elapsed_ms(started),
            "message": message,
            "host": config.host,
            "port": config.port,
        },
    )
    print(message)
    return 0


def load_healthcheck_settings_from_env() -> HealthcheckSettings:
    pushover_app_token, app_token_error = optional_env_secret("PUSHOVER_APP_TOKEN")
    pushover_user_key, user_key_error = optional_env_secret("PUSHOVER_USER_KEY")

    return HealthcheckSettings(
        history_path=os.environ.get("SMTP_PROXY_HEALTHCHECK_HISTORY_PATH", DEFAULT_HISTORY_PATH),
        history_max_bytes=env_int("SMTP_PROXY_HEALTHCHECK_HISTORY_MAX_BYTES", DEFAULT_HISTORY_MAX_BYTES),
        state_path=os.environ.get("SMTP_PROXY_HEALTHCHECK_STATE_PATH", DEFAULT_STATE_PATH),
        alert_after_failures=env_int("SMTP_PROXY_HEALTHCHECK_ALERT_AFTER_FAILURES", DEFAULT_ALERT_AFTER_FAILURES),
        pushover_enabled=env_bool("SMTP_PROXY_HEALTHCHECK_PUSHOVER_ENABLED", False),
        pushover_app_token=pushover_app_token,
        pushover_user_key=pushover_user_key,
        pushover_device=os.environ.get("PUSHOVER_DEVICE", ""),
        pushover_priority=env_int("PUSHOVER_PRIORITY", 0),
        pushover_title=os.environ.get("PUSHOVER_TITLE", "SimpleLogin SMTP proxy"),
        pushover_timeout_seconds=env_float("PUSHOVER_TIMEOUT_SECONDS", 5.0),
        pushover_recovery_enabled=env_bool("SMTP_PROXY_HEALTHCHECK_PUSHOVER_RECOVERY_ENABLED", True),
        pushover_config_error="; ".join(error for error in (app_token_error, user_key_error) if error),
    )


def optional_env_secret(name: str) -> Tuple[str, str]:
    try:
        return env_secret(name, ""), ""
    except SecretFileError as exc:
        return "", str(exc)


def record_healthcheck_result(
    settings: HealthcheckSettings,
    event: Dict[str, object],
    alert_sender: Optional[Callable[[HealthcheckSettings, str, str], None]] = None,
) -> Dict[str, object]:
    state = load_healthcheck_state(settings.state_path)
    status = str(event.get("status", ""))
    previous_failures = int(state.get("consecutive_failures", 0) or 0)
    previously_alerted = bool(state.get("alerted_unhealthy", False))

    if status == "ok":
        consecutive_failures = 0
        alert_kind = "recovered" if previously_alerted and settings.pushover_recovery_enabled else ""
        state = {
            "consecutive_failures": 0,
            "alerted_unhealthy": False,
            "last_ok_at": event.get("timestamp", utc_timestamp()),
        }
    else:
        consecutive_failures = previous_failures + 1
        alert_kind = ""
        if (
            settings.alert_after_failures > 0
            and consecutive_failures >= settings.alert_after_failures
            and not previously_alerted
        ):
            alert_kind = "unhealthy"
        state = {
            "consecutive_failures": consecutive_failures,
            "alerted_unhealthy": previously_alerted,
            "last_failure_at": event.get("timestamp", utc_timestamp()),
            "last_failure": event.get("message", ""),
        }

    event["consecutive_failures"] = consecutive_failures
    event["alert"] = alert_kind or "none"

    if alert_kind:
        alert_status = send_healthcheck_alert(settings, alert_kind, event, alert_sender=alert_sender)
        event["pushover"] = alert_status["status"]
        if "error" in alert_status:
            event["pushover_error"] = alert_status["error"]
        if alert_kind == "unhealthy" and alert_status["status"] == "sent":
            state["alerted_unhealthy"] = True
        if alert_kind == "recovered":
            state["alerted_unhealthy"] = False

    save_healthcheck_state(settings.state_path, state)
    append_healthcheck_history(settings.history_path, event, max_bytes=settings.history_max_bytes)
    return event


def send_healthcheck_alert(
    settings: HealthcheckSettings,
    alert_kind: str,
    event: Dict[str, object],
    alert_sender: Optional[Callable[[HealthcheckSettings, str, str], None]] = None,
) -> Dict[str, str]:
    if not settings.pushover_enabled:
        return {"status": "disabled"}
    if settings.pushover_config_error:
        return {"status": "skipped", "error": settings.pushover_config_error}
    if not settings.pushover_app_token or not settings.pushover_user_key:
        return {"status": "skipped", "error": "Pushover token and user key are required"}

    title = settings.pushover_title
    message = healthcheck_alert_message(alert_kind, event)
    try:
        sender = alert_sender or send_pushover_message
        sender(settings, title, message)
    except Exception as exc:
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}"[:300]}
    return {"status": "sent"}


def healthcheck_alert_message(alert_kind: str, event: Dict[str, object]) -> str:
    if alert_kind == "recovered":
        return "SMTP proxy healthcheck recovered."

    failures = event.get("consecutive_failures", "?")
    detail = str(event.get("message", "healthcheck failed"))
    return f"SMTP proxy healthcheck failed {failures} consecutive times. Latest result: {detail}"


def send_pushover_message(settings: HealthcheckSettings, title: str, message: str) -> None:
    payload = {
        "token": settings.pushover_app_token,
        "user": settings.pushover_user_key,
        "title": title,
        "message": message,
        "priority": str(settings.pushover_priority),
    }
    if settings.pushover_device:
        payload["device"] = settings.pushover_device

    body = urlencode(payload).encode("utf-8")
    request = Request(PUSHOVER_API_URL, data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urlopen(request, timeout=settings.pushover_timeout_seconds):
        return


def append_healthcheck_history(path: str, event: Dict[str, object], max_bytes: int = DEFAULT_HISTORY_MAX_BYTES) -> None:
    if not path:
        return
    try:
        ensure_parent_dir(path)
        rotate_file_if_needed(path, max_bytes=max_bytes)
        with open(path, "a", encoding="utf-8") as history:
            history.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
    except OSError:
        return


def load_healthcheck_state(path: str) -> Dict[str, object]:
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as state_file:
            loaded = json.load(state_file)
    except (OSError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def save_healthcheck_state(path: str, state: Dict[str, object]) -> None:
    if not path:
        return
    try:
        ensure_parent_dir(path)
        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as state_file:
            json.dump(state, state_file, sort_keys=True, separators=(",", ":"))
            state_file.write("\n")
        os.replace(tmp_path, path)
    except OSError:
        return


def rotate_file_if_needed(path: str, max_bytes: int) -> None:
    if max_bytes <= 0:
        return
    try:
        if os.path.getsize(path) < max_bytes:
            return
    except OSError:
        return
    os.replace(path, f"{path}.1")


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def elapsed_ms(started_monotonic: float) -> int:
    return int((time.monotonic() - started_monotonic) * 1000)


def _connect_host(host: str) -> str:
    if host in {"", "0.0.0.0", "::"}:
        return "127.0.0.1"
    return host


def _wrap_implicit_tls_if_needed(
    sock: socket.socket,
    config: SmtpProxyConfig,
    host: str,
) -> Union[socket.socket, ssl.SSLSocket]:
    tls_requested = config.require_tls or bool(config.tls_cert_file or config.tls_key_file)
    if not tls_requested or config.tls_mode.strip().lower() != "implicit":
        return sock

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(sock, server_hostname=host)


def _readline(sock: Union[socket.socket, ssl.SSLSocket]) -> bytes:
    line = b""
    while not line.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        line += chunk
        if len(line) > 1024:
            raise HealthcheckError("SMTP proxy banner was too long")
    return line


if __name__ == "__main__":
    raise SystemExit(main())
