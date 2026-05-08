from __future__ import annotations

from typing import Iterable


class SimpleLoginError(RuntimeError):
    pass


class SimpleLoginConfigError(SimpleLoginError):
    pass


class SimpleLoginApiError(SimpleLoginError):
    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.status_code = status_code


def redact_values(value: str, secrets: Iterable[str]) -> str:
    redacted = value
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted
