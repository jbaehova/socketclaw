"""Fixed source-format fixtures, including ambiguous address and clock cases."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from socketclaw.probes.log_parser import PARSER_VERSION, parse_log_line
from socketclaw.probes.logs import _event_for_line, preview_log


def test_openssh_uses_labeled_source_instead_of_first_ip_and_normalizes_time() -> None:
    line = (
        "2026-09-17T10:20:30.123+09:00 10.0.0.2 sshd[42]: "
        "Failed password for invalid user admin from 2001:0db8::7 port 50322 ssh2"
    )
    result = parse_log_line(line)
    assert result.parser == "openssh"
    assert result.parse_quality == "structured"
    assert result.source_ip == "2001:db8::7"
    assert result.destination_ip is None
    assert result.user == "admin"
    assert result.action == "authentication_failure"
    assert result.source_at == datetime(2026, 9, 17, 1, 20, 30, 123000, tzinfo=UTC)
    assert result.source_time_quality == "explicit_timezone"


def test_firewall_source_and_destination_are_independent_of_field_order() -> None:
    result = parse_log_line(
        "2026-09-17T01:20:30Z gateway kernel: [UFW BLOCK] IN=eth0 OUT= "
        "DST=10.0.0.2 SRC=192.0.2.9 PROTO=TCP DPT=22"
    )
    assert result.parser == "linux_firewall"
    assert result.parse_quality == "structured"
    assert result.source_ip == "192.0.2.9"
    assert result.destination_ip == "10.0.0.2"
    assert result.action == "deny"
    event = _event_for_line(
        Path("/tmp/firewall.log"), "kernel: [UFW BLOCK] DST=10.0.0.2 SRC=192.0.2.9", False
    )
    assert event is not None
    assert event.event_type == "log.firewall_denial"
    assert event.target == "192.0.2.9"


def test_pam_rhost_is_explicit_but_a_hostname_does_not_become_an_ip() -> None:
    line = (
        "sshd[42]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 rhost=192.0.2.10 user=root"
    )
    result = parse_log_line(line)
    assert result.parser == "pam_unix"
    assert result.source_ip == "192.0.2.10"
    assert result.user == "root"
    unknown = parse_log_line(line.replace("192.0.2.10", "client.example"))
    assert unknown.source_ip is None
    assert unknown.parse_quality == "partial"


@pytest.mark.parametrize(
    "prefix, quality",
    [
        ("Sep 17 01:20:30 server sshd[42]: ", "missing_year_timezone"),
        ("2026-09-17T01:20:30 server sshd[42]: ", "missing_timezone"),
        ("2026-99-17T01:20:30Z server sshd[42]: ", "invalid"),
        ("", "missing"),
    ],
)
def test_incomplete_timestamps_do_not_invent_date_or_timezone(prefix: str, quality: str) -> None:
    result = parse_log_line(prefix + "Failed password for root from 192.0.2.1 port 22")
    assert result.source_at is None
    assert result.source_time_quality == quality
    assert result.source_ip == "192.0.2.1"


@pytest.mark.parametrize(
    "line",
    [
        "destination 10.0.0.2 reports authentication failure for peer 192.0.2.1",
        "application: example Failed password for root from 192.0.2.1",
        "malware 192.0.2.1 was mentioned by 10.0.0.2",
    ],
)
def test_unknown_formats_keep_keyword_detection_without_actor_inference(line: str) -> None:
    result = parse_log_line(line)
    assert result.parse_quality == "unparsed"
    assert result.source_ip is None
    assert result.destination_ip is None
    event = _event_for_line(Path("/tmp/security.log"), line, False)
    assert event is not None
    assert event.target is None
    assert event.evidence["parse_quality"] == "unparsed"
    assert event.evidence["parser_version"] == PARSER_VERSION


@pytest.mark.parametrize(
    "line",
    [
        "authentication failure from 999.999.999.999",
        "Failed password for root from 192.0.2.1.attacker.example port 22",
        "Failed password for root from fe80::1%en0 port 22",
        "DROP SRC=192.0.2.1 SRC=192.0.2.2 DST=10.0.0.2",
    ],
)
def test_invalid_or_ambiguous_source_never_falls_back_to_another_address(line: str) -> None:
    result = parse_log_line(line)
    assert result.source_ip is None
    assert result.parse_quality == "partial"


def test_event_keeps_observation_and_source_times_distinct() -> None:
    event = _event_for_line(
        Path("/tmp/auth.log"),
        "2020-01-01T00:00:00Z host sshd[1]: Failed password for root from 192.0.2.1",
        False,
    )
    assert event is not None
    assert event.source_at == datetime(2020, 1, 1, tzinfo=UTC)
    assert event.observed_at > event.source_at


@pytest.mark.parametrize("stamp", ["0001-01-01T00:00:00+23:00", "9999-12-31T23:59:59-23:00"])
def test_out_of_range_utc_conversion_cannot_block_the_collector(stamp: str) -> None:
    result = parse_log_line(stamp + " Failed password for root from 192.0.2.1")
    assert result.source_at is None
    assert result.source_time_quality == "invalid"
    assert result.source_ip == "192.0.2.1"


def test_truncated_username_is_not_recorded_as_a_different_account() -> None:
    result = parse_log_line("Failed password for " + "x" * 129 + " from 192.0.2.1")
    assert result.user is None
    assert result.parse_quality == "partial"


async def test_preview_ignores_incomplete_last_line_and_refuses_nonfiles(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("authentication failure from 192.0.2.1\nFailed password for root")
    preview = await preview_log(path)
    assert preview.complete_lines == 1
    assert len(preview.matches) == 1
    assert preview.limited
    with pytest.raises(OSError, match="regular file"):
        await preview_log(tmp_path)


async def test_preview_refuses_symbolic_links(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_text("Failed password\n")
    link = tmp_path / "linked.log"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("This environment cannot create a symbolic link fixture")
    with pytest.raises(OSError, match="regular file"):
        await preview_log(link)
