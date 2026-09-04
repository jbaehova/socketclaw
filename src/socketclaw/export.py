"""Deterministic, secret-safe incident exports."""

from __future__ import annotations

import html
import json
import os
import re
import stat
import unicodedata
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path
from typing import cast
from uuid import uuid4

from .openai import redact_secrets
from .storage import StoredEvent, StoredInvestigation, StoredResponseProposal


def write_managed_export(home: Path, filename: str, content: str) -> Path:
    """Atomically write below the private managed export directory."""
    if Path(filename).name != filename or filename in {"", ".", ".."}:
        raise ValueError("managed export filename must be one path component")
    rendered = content.encode("utf-8")
    if os.name == "posix":
        _write_managed_export_posix(home, filename, rendered)
    else:
        _write_managed_export_portable(home, filename, content)
    return home / "exports" / filename


def _write_managed_export_posix(home: Path, filename: str, content: bytes) -> None:
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    home_fd = os.open(home, directory_flags)
    directory_fd: int | None = None
    temporary_fd: int | None = None
    temporary_name = f".{filename}.{uuid4().hex}.tmp"
    try:
        home_status = os.fstat(home_fd)
        if not stat.S_ISDIR(home_status.st_mode):
            raise OSError("SocketClaw home must be a directory")
        if home_status.st_uid != os.getuid():
            raise OSError("SocketClaw home must be owned by the current user")
        with suppress(FileExistsError):
            os.mkdir("exports", mode=0o700, dir_fd=home_fd)
        directory_fd = os.open("exports", directory_flags, dir_fd=home_fd)
        directory_status = os.fstat(directory_fd)
        if not stat.S_ISDIR(directory_status.st_mode):
            raise OSError("managed export path must be a directory")
        if directory_status.st_uid != os.getuid():
            raise OSError("managed export directory must be owned by the current user")
        os.fchmod(directory_fd, 0o700)

        file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        file_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        temporary_fd = os.open(
            temporary_name,
            file_flags,
            0o600,
            dir_fd=directory_fd,
        )
        offset = 0
        while offset < len(content):
            written = os.write(temporary_fd, content[offset:])
            if written <= 0:
                raise OSError("managed export write made no progress")
            offset += written
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None
        os.replace(
            temporary_name,
            filename,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    finally:
        if temporary_fd is not None:
            with suppress(OSError):
                os.close(temporary_fd)
        if directory_fd is not None:
            with suppress(OSError):
                os.unlink(temporary_name, dir_fd=directory_fd)
            with suppress(OSError):
                os.close(directory_fd)
        with suppress(OSError):
            os.close(home_fd)


def _write_managed_export_portable(_home: Path, _filename: str, _content: str) -> None:
    raise OSError(
        "secure automatic exports require POSIX directory handles; "
        "use the CLI with an explicit --output path"
    )


def export_json(
    event: StoredEvent,
    investigation: StoredInvestigation | None,
    *,
    response_proposal: StoredResponseProposal | None = None,
    secrets: Sequence[str] = (),
) -> str:
    """Export one incident as stable, redacted JSON."""
    _validate_investigation(investigation)
    _validate_response_proposal(event, investigation, response_proposal)
    payload = {
        "event": event.model_dump(mode="json"),
        "investigation": (
            investigation.model_dump(mode="json") if investigation is not None else None
        ),
        "response_proposal": (
            response_proposal.model_dump(mode="json") if response_proposal is not None else None
        ),
    }
    redacted_payload = _redact_data(payload, secrets)
    rendered = json.dumps(
        redacted_payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    return rendered + "\n"


def export_markdown(
    event: StoredEvent,
    investigation: StoredInvestigation | None,
    *,
    response_proposal: StoredResponseProposal | None = None,
    secrets: Sequence[str] = (),
) -> str:
    """Export one incident as an operator-readable Markdown report."""
    _validate_investigation(investigation)
    _validate_response_proposal(event, investigation, response_proposal)

    def text(value: str) -> str:
        return _markdown_text(_redacted_text(value, secrets, preserve_layout=True))

    def code(value: str) -> str:
        return _code_span(_redacted_text(value, secrets, preserve_layout=True))

    signal_lines = (
        "\n".join(
            f"- {code(signal.code)} (+{signal.points}) - {text(signal.detail)}"
            for signal in event.signals
        )
        or "- No deterministic detection signals were recorded."
    )
    evidence = json.dumps(
        _redact_data(event.evidence, secrets),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    evidence_block = _fenced_block(evidence, "json")
    sections = [
        "# SocketClaw Incident",
        "",
        f"**Event ID:** {code(str(event.id))}  ",
        f"**Observed:** {text(event.observed_at.isoformat())}  ",
        f"**Severity:** {event.severity.value.upper()} ({event.score}/100)  ",
        f"**Source:** {code(event.source.value)}  ",
        f"**Target:** {text(event.target or '-')}",
        "",
        f"## {text(event.title)}",
        "",
        text(event.summary),
        "",
        "## Detection signals",
        "",
        signal_lines,
        "",
        "## Evidence",
        "",
        *evidence_block,
        "",
    ]
    if investigation is None:
        sections.extend(
            [
                "## AI investigation",
                "",
                "No AI investigation has been recorded.",
                "",
            ]
        )
    elif investigation.status in {"queued", "running"}:
        state = investigation.status.title()
        sections.extend(
            [
                "## AI investigation",
                "",
                f"**Status:** {state}  ",
                f"**Model:** {code(investigation.model_id)}  ",
                f"**Reasoning effort:** {code(investigation.requested_effort)}",
                "",
                f"The investigation is currently {investigation.status}.",
                "",
            ]
        )
    elif investigation.status == "failed":
        sections.extend(
            [
                "## AI investigation",
                "",
                "**Status:** Failed  ",
                f"**Model:** {code(investigation.model_id)}  ",
                f"**Reasoning effort:** {code(investigation.requested_effort)}",
                "",
                text(investigation.error or "The provider did not return an error message."),
                "",
            ]
        )
    else:
        assessment = investigation.assessment
        usage = investigation.usage
        if assessment is None or usage is None:
            raise ValueError("complete investigation is missing assessment or usage")
        rationale = "\n".join(f"- {text(item)}" for item in assessment.rationale)
        actions = (
            "\n".join(f"- {text(item)}" for item in assessment.recommended_actions)
            or "- No additional action was recommended."
        )
        sections.extend(
            [
                "## AI investigation",
                "",
                f"**Model:** {code(investigation.model_id)}  ",
                f"**Reasoning effort:** {code(investigation.requested_effort)}  ",
                f"**Classification:** {text(assessment.classification.upper())}  ",
                f"**Confidence:** {assessment.confidence:.0%}  ",
                f"**Tokens:** {usage.total_tokens or 0}  ",
                f"**Estimated cost:** ${usage.cost_usd:.6f}  ",
                f"**Latency:** {usage.latency_ms} ms",
                "",
                text(assessment.summary),
                "",
                "### Rationale",
                "",
                rationale,
                "",
                "### Recommended actions",
                "",
                actions,
                "",
            ]
        )
        proposal = (
            response_proposal.proposal
            if response_proposal is not None
            else assessment.response_proposal
        )
        if proposal is not None:
            sections.extend(
                [
                    "### Response proposal",
                    "",
                    f"**Action:** {text(proposal.action.title())}  ",
                    f"**Target:** {text(proposal.target_ip or '-')}  ",
                    f"**Reversible:** {'Yes' if proposal.reversible else 'No'}  ",
                    f"**Approval required:** {'Yes' if proposal.requires_approval else 'No'}",
                ]
            )
            if response_proposal is not None:
                sections.extend(
                    [
                        f"**Proposal ID:** {code(str(response_proposal.id))}  ",
                        f"**Durable status:** {text(response_proposal.status.title())}  ",
                        f"**Recorded:** {code(response_proposal.created_at.isoformat())}",
                    ]
                )
            if proposal.platform is not None:
                sections.append(f"**Platform:** {code(proposal.platform)}")
            sections.extend(["", text(proposal.reason), ""])
            if proposal.command is not None:
                safe_command = _redacted_text(
                    proposal.command,
                    secrets,
                    preserve_layout=True,
                )
                sections.extend(
                    [
                        "**Proposed command:**",
                        "",
                        *_fenced_block(safe_command, "text"),
                        "",
                    ]
                )
    return "\n".join(sections).rstrip() + "\n"


def _redact_data(value: object, secrets: Sequence[str]) -> object:
    """Redact nested string data before serialization so JSON remains valid."""
    if isinstance(value, str):
        return _redacted_text(value, secrets, preserve_layout=True)
    if isinstance(value, dict):
        mapping = cast(dict[object, object], value)
        redacted: dict[object, object] = {}
        for key, nested in mapping.items():
            candidate = _redacted_text(key, secrets) if isinstance(key, str) else key
            if isinstance(candidate, str) and candidate in redacted:
                base = candidate
                suffix = 2
                while candidate in redacted:
                    candidate = f"{base} #{suffix}"
                    suffix += 1
            redacted[candidate] = _redact_data(nested, secrets)
        return redacted
    if isinstance(value, list | tuple):
        items = cast(Sequence[object], value)
        return [_redact_data(nested, secrets) for nested in items]
    return value


def _validate_investigation(investigation: StoredInvestigation | None) -> None:
    if investigation is None or investigation.status != "complete":
        return
    if investigation.assessment is None or investigation.usage is None:
        raise ValueError("complete investigation is missing assessment or usage")


def _validate_response_proposal(
    event: StoredEvent,
    investigation: StoredInvestigation | None,
    response_proposal: StoredResponseProposal | None,
) -> None:
    if response_proposal is None:
        return
    if response_proposal.event_id != event.id:
        raise ValueError("response proposal does not belong to the exported event")
    if investigation is None or response_proposal.investigation_id != investigation.id:
        raise ValueError("response proposal does not belong to the exported investigation")


def _single_line(value: str) -> str:
    """Keep untrusted incident text inside its intended Markdown block."""
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    normalized = normalized.replace("\n", " ").replace("\t", " ")
    return _strip_terminal_controls(normalized)


def _markdown_text(value: str) -> str:
    """Render untrusted text literally rather than as Markdown or raw HTML."""
    escaped = html.escape(_single_line(value), quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|>-])", r"\\\1", escaped)


def _code_span(value: str) -> str:
    """Render arbitrary single-line text in a valid CommonMark code span."""
    normalized = _single_line(value)
    runs = re.findall(r"`+", normalized)
    delimiter = "`" * (max((len(run) for run in runs), default=0) + 1)
    padding = " " if normalized.startswith("`") or normalized.endswith("`") else ""
    return f"{delimiter}{padding}{normalized}{padding}{delimiter}"


def _fenced_block(value: str, language: str) -> list[str]:
    """Wrap literal content in a fence that the content itself cannot close."""
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    normalized = _strip_terminal_controls(normalized, preserve_layout=True)
    runs = re.findall(r"`+", normalized)
    delimiter = "`" * max(3, max((len(run) for run in runs), default=0) + 1)
    return [f"{delimiter}{language}", normalized, delimiter]


def _strip_terminal_controls(value: str, *, preserve_layout: bool = False) -> str:
    """Remove terminal-active C0/C1 controls from untrusted export text."""
    safe: list[str] = []
    for character in value:
        if preserve_layout and character in {"\n", "\t"}:
            safe.append(character)
            continue
        codepoint = ord(character)
        if codepoint < 0x20 or 0x7F <= codepoint <= 0x9F or unicodedata.category(character) == "Cf":
            continue
        safe.append(character)
    return "".join(safe)


def _redacted_text(
    value: str,
    secrets: Sequence[str],
    *,
    preserve_layout: bool = False,
) -> str:
    """Redact both before and after normalization can join separated tokens."""
    initially_redacted = redact_secrets(value, secrets)
    normalized = _strip_terminal_controls(
        initially_redacted,
        preserve_layout=preserve_layout,
    )
    return redact_secrets(normalized, secrets)
