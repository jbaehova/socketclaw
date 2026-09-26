"""Outbound-copy credential filtering. Local evidence is never modified.

Identity fields (addresses, accounts, event IDs) remain explicit to preserve linkage.
This is a documented recognizer, not a promise to detect arbitrary secrets.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import cast

_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_AUTH_HEADER = re.compile(r"(?im)(\bauthorization\s*:\s*)(?!\s*(?:Bearer|Basic)\b)[^\r\n]+")
_KNOWN_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[A-Z0-9]{16}|"
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b"
)
_URL_USERINFO = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^\s/@]+@")
_CREDENTIAL = re.compile(
    r"""(?ix)(\b(?:password|passwd|pwd|passphrase|token|access[_-]?token|refresh[_-]?token|
    api[_-]?key|secret|client[_-]?secret|session(?:[_-]?id)?)\b["']?\s*[:=]\s*)
    (?:\[REDACTED\]|"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&}\]]+)"""
)
_COOKIE = re.compile(r"(?im)(\b(?:set-cookie|cookie)\s*:\s*)[^\r\n]+")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----", re.S
)
_SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "token",
    "accesstoken",
    "refreshtoken",
    "apikey",
    "secret",
    "clientsecret",
    "session",
    "sessionid",
    "cookie",
    "setcookie",
    "authorization",
    "proxyauthorization",
    "privatekey",
    "credential",
    "credentials",
}


def sensitive_field(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return normalized in _SENSITIVE_KEYS or normalized.endswith(
        ("password", "passwd", "apikey", "secret", "secretaccesskey", "accesstoken", "refreshtoken")
    )


def redact_secrets(text: str, secrets: Sequence[str] = ()) -> str:
    redacted = text
    for secret in sorted((value for value in secrets if value), key=len, reverse=True):
        redacted = redacted.replace(secret, "[REDACTED]")
    redacted = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", redacted)
    redacted = _KNOWN_TOKEN.sub("[REDACTED]", redacted)
    redacted = _AUTH_HEADER.sub(r"\1[REDACTED]", redacted)
    redacted = _OPENAI_KEY.sub("[REDACTED]", redacted)
    redacted = _BEARER.sub(lambda m: f"{m[1]} [REDACTED]", redacted)
    redacted = _URL_USERINFO.sub(r"\1[REDACTED]@", redacted)
    redacted = _COOKIE.sub(r"\1[REDACTED]", redacted)
    return _CREDENTIAL.sub(r"\1[REDACTED]", redacted)


def redact_data(value: object, secrets: Sequence[str] = ()) -> object:
    """Recursively redact credential fields and recognizable text credentials."""
    if isinstance(value, str):
        return redact_secrets(value, secrets)
    if isinstance(value, dict):
        result: dict[object, object] = {}
        for key, item in cast(dict[object, object], value).items():
            candidate = redact_secrets(key, secrets) if isinstance(key, str) else key
            if isinstance(candidate, str) and candidate in result:
                base, suffix = candidate, 2
                while candidate in result:
                    candidate = f"{base} #{suffix}"
                    suffix += 1
            result[candidate] = (
                "[REDACTED]"
                if isinstance(key, str) and sensitive_field(key)
                else redact_data(item, secrets)
            )
        return result
    if isinstance(value, list | tuple):
        return [redact_data(item, secrets) for item in cast(Sequence[object], value)]
    return value
