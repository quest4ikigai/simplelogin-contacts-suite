from __future__ import annotations

import os
import socket
import ssl
import sys
from typing import Union

from .config import SmtpProxyConfig, load_config_from_env


DEFAULT_TIMEOUT_SECONDS = 5.0


class HealthcheckError(RuntimeError):
    pass


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
    timeout_seconds = float(os.environ.get("SMTP_PROXY_HEALTHCHECK_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS))
    try:
        check_health(config, timeout_seconds=timeout_seconds)
    except Exception as exc:
        print(f"healthcheck failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print("healthcheck ok")
    return 0


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
