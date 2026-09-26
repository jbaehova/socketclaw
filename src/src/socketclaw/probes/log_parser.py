"""Conservative field extraction for explicit authentication and firewall formats."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PARSER_VERSION = 3

_ISO_PREFIX = re.compile(r"^(\d{4}-\d{2}-\d{2}T\S+)\s+")
_ISO_AWARE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})")
_SYSLOG_PREFIX = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+")
_PROCESS_PREFIX = re.compile(
    r"^(?:(?P<host>\S+)\s+)?(?P<process>sshd(?:-session)?|kernel|sudo|su|clamd|clamav|clamscan|useradd|usermod|userdel)"
    r"(?:\[(?P<pid>\d+)\])?:\s*",
    re.I,
)
_SSH_SUCCESS = re.compile(
    r"^Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) "
    r"from (?P<source>\S+)(?: port (?P<port>\d+))?(?: ssh2)?(?:\s|$)",
    re.I,
)
_PAM_SESSION = re.compile(
    r"^pam_unix\([\w-]+:session\): session (?P<state>opened|closed) for user (?P<user>[^\s(]+)",
    re.I,
)
_SUDO_COMMAND = re.compile(
    r"^\s*(?P<user>[^\s:]+)\s*:\s*.*(?:^|;)\s*COMMAND=(?P<command>.+)$", re.I
)
_CLAM_FOUND = re.compile(r"^(?P<file>.+): (?P<signature>[^:]+) FOUND$", re.I)
_ACCOUNT = re.compile(r"^(?:new user|delete user|change user).*?name=(?P<user>[^,\s]+)", re.I)

_SSH_FAILURE = re.compile(
    r"^Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<source>\S+)(?: port \d+)?(?: ssh2)?(?:\s|$)",
    re.I,
)
_AUTH_FROM = re.compile(r"^authentication failure from (?P<source>\S+)\s*$", re.I)
_PAM_FAILURE = re.compile(r"^pam_unix\([\w-]+:auth\): authentication failure;(?P<fields>.*)$", re.I)
_FIELD = re.compile(r"(?:^|\s)(?P<key>SRC|DST|rhost|user)=(?P<value>\S*)", re.I)
_DENIAL = re.compile(r"(?:\bDROP\b|\bREJECT\b|\[UFW BLOCK\]|\bfirewall.*\bden(?:y|ied)\b)", re.I)


class ParsedLog(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    parser_version: int = PARSER_VERSION
    parser: str = "generic"
    parse_quality: Literal["structured", "partial", "unparsed"] = "unparsed"
    source_at: datetime | None = None
    source_time_quality: Literal[
        "explicit_timezone", "missing", "missing_year_timezone", "missing_timezone", "invalid"
    ] = "missing"
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = Field(default=None, max_length=128)
    action: str | None = None
    asset: str | None = None
    process: str | None = None
    pid: int | None = None
    command: str | None = None
    session_id: str | None = None
    file: str | None = None
    signature: str | None = None
    result: str | None = None


def parse_log_line(line: str) -> ParsedLog:
    """Unknown formats retain no inferred actor, even when they contain IP addresses."""
    line = line[:65536]
    payload, source_at, time_quality = _timestamp_prefix(line)
    process_match = _PROCESS_PREFIX.match(payload)
    asset = process = None
    pid = None
    invalid_process_fields = False
    if process_match:
        asset, process = process_match["host"], process_match["process"].casefold()
        raw_pid = process_match["pid"]
        if raw_pid is not None:
            # An untrusted identifier cannot trigger Python's giant-integer
            # conversion guard or manufacture an impossible operating-system PID.
            if len(raw_pid) <= 10 and 0 < int(raw_pid) <= 2**31 - 1:
                pid = int(raw_pid)
            else:
                invalid_process_fields = True
        if asset is not None and len(asset) > 253:
            asset = None
            invalid_process_fields = True
        payload = payload[process_match.end() :]
    parser = "generic"
    command = session_id = file = signature = result = None
    source = destination = user = None
    action: str | None = None
    ssh = _SSH_FAILURE.match(payload)
    success = _SSH_SUCCESS.match(payload)
    session = _PAM_SESSION.match(payload)
    sudo = _SUDO_COMMAND.match(payload) if process == "sudo" else None
    clam = _CLAM_FOUND.fullmatch(payload)
    account = _ACCOUNT.match(payload) if process in {"useradd", "usermod", "userdel"} else None
    auth = _AUTH_FROM.fullmatch(payload)
    pam = _PAM_FAILURE.fullmatch(payload)
    fields = _fields(payload)
    if ssh:
        parser, action = "openssh", "authentication_failure"
        source = _address(ssh["source"])
        user = ssh["user"] if len(ssh["user"]) <= 128 else None
    elif success:
        parser, action = "openssh", "authentication_success"
        source, user = _address(success["source"]), success["user"]
        session_id = f"{process}:{pid}" if pid is not None else None
    elif session:
        parser, action = "pam_unix", "session_" + session["state"].casefold()
        user = session["user"]
        session_id = f"{process}:{pid}" if pid is not None else None
    elif sudo:
        parser, action = "sudo", "sudo_execution"
        user, command = sudo["user"], sudo["command"][:4000]
    elif clam and (process in {"clamd", "clamav", "clamscan"} or payload.startswith("/")):
        parser, action, result = "clamav", "malware_detected", "found"
        file, signature = clam["file"][:4000], clam["signature"][:500]
    elif process in {"clamd", "clamav", "clamscan"} and (
        re.search(
            r"(?:Infected files:\s*0\b|: OK$|no (?:malware|virus(?:es)?) found)", payload, re.I
        )
    ):
        parser, action, result = "clamav", "scan_clean", "clean"
    elif account:
        parser, action, user = "account", "account_change", account["user"]
    elif auth:
        parser, action = "authentication_from", "authentication_failure"
        source = _address(auth["source"])
    elif pam:
        parser, action = "pam_unix", "authentication_failure"
        fields = _fields(pam["fields"])
        source = _address(_one(fields, "rhost"))
        user = _one(fields, "user") or None
        if user is not None and len(user) > 128:
            user = None
    elif _DENIAL.search(payload) and ("src" in fields or "dst" in fields):
        parser, action = "linux_firewall", "deny"
        source, destination = _address(_one(fields, "src")), _address(_one(fields, "dst"))
    if user is not None and len(user) > 128:
        user = None
    quality = "unparsed" if parser == "generic" else "structured"
    if parser != "generic" and (
        invalid_process_fields
        or (
            source is None
            and action in {"authentication_failure", "authentication_success", "deny"}
        )
        or time_quality == "invalid"
        or (parser == "linux_firewall" and destination is None)
        or (parser in {"openssh", "pam_unix"} and user is None)
    ):
        quality = "partial"
    return ParsedLog(
        parser=parser,
        parse_quality=quality,
        source_at=source_at,
        source_time_quality=time_quality,
        source_ip=source,
        destination_ip=destination,
        user=user,
        action=action,
        asset=asset,
        process=process,
        pid=pid,
        command=command,
        session_id=session_id,
        file=file,
        signature=signature,
        result=result,
    )


def _fields(payload: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for field in _FIELD.finditer(payload):
        result.setdefault(field["key"].casefold(), []).append(field["value"])
    return result


def _one(fields: dict[str, list[str]], key: str) -> str | None:
    values = fields.get(key, [])
    return values[0] if len(values) == 1 else None


def _address(value: str | None) -> str | None:
    if value is None or "%" in value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _timestamp_prefix(
    line: str,
) -> tuple[
    str,
    datetime | None,
    Literal["explicit_timezone", "missing", "missing_year_timezone", "missing_timezone", "invalid"],
]:
    iso = _ISO_PREFIX.match(line)
    if iso:
        stamp = iso[1]
        payload = line[iso.end() :]
        try:
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            return payload, None, "invalid"
        if parsed.tzinfo is None:
            return payload, None, "missing_timezone"
        if not _ISO_AWARE.fullmatch(stamp):
            return payload, None, "invalid"
        try:
            normalized = parsed.astimezone(UTC)
        except (OverflowError, ValueError):
            return payload, None, "invalid"
        return payload, normalized, "explicit_timezone"
    syslog = _SYSLOG_PREFIX.match(line)
    if syslog:
        return line[syslog.end() :], None, "missing_year_timezone"
    return line, None, "missing"
