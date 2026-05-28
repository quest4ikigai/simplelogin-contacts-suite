from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Union

from .config import SmtpProxyConfig, env_int, load_config_from_env


DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_HISTORY_PATH = "/data/healthcheck.jsonl"
DEFAULT_HISTORY_MAX_BYTES = 5 * 1024 * 1024


class HealthcheckError(RuntimeError):
    pass


@dataclass
class HealthcheckSettings:
    history_path: str = DEFAULT_HISTORY_PATH
    history_max_bytes: int = DEFAULT_HISTORY_MAX_BYTES


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
    return HealthcheckSettings(
        history_path=os.environ.get("SMTP_PROXY_HEALTHCHECK_HISTORY_PATH", DEFAULT_HISTORY_PATH),
        history_max_bytes=env_int("SMTP_PROXY_HEALTHCHECK_HISTORY_MAX_BYTES", DEFAULT_HISTORY_MAX_BYTES),
    )


def record_healthcheck_result(settings: HealthcheckSettings, event: Dict[str, object]) -> Dict[str, object]:
    append_healthcheck_history(settings.history_path, event, max_bytes=settings.history_max_bytes)
    return event


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
