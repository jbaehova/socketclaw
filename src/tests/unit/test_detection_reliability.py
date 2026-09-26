"""Regression corpus for the reliability audit, without external services."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from socketclaw.detection import Detector, correlation_basis, correlation_time
from socketclaw.domain import SecurityEvent, Severity
from socketclaw.probes.log_parser import parse_log_line
from socketclaw.probes.logs import _event_for_line
from socketclaw.replay import replay_events
from socketclaw.rules import RuleConfig

NOW = datetime(2026, 9, 26, 12, tzinfo=UTC)


def log(line: str) -> SecurityEvent:
    event = _event_for_line(Path("/tmp/auth.log"), line, False)
    assert event is not None
    return event.model_copy(update={"observed_at": NOW, "ingested_at": NOW})


@pytest.mark.parametrize(
    "prefix",
    [
        "sudo: ",
        "sudo[1234]: ",
        "Sep 26 12:00:00 host sudo[1234]: ",
        "2026-09-26T12:00:00Z host sudo: ",
    ],
)
def test_sudo_execution_is_not_authentication_failure(prefix):
    event = log(prefix + "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash")
    assert event.event_type == "log.sudo_execution"
    assert event.evidence["command"] == "/bin/bash"
    assert event.evidence["user"] == "alice"
    assert Detector().score(event, []).score == 0


def test_sudo_pam_failure_preserves_fields_without_privilege_signal():
    event = log(
        "sudo[1234]: pam_unix(sudo:auth): authentication failure; "
        "logname=alice rhost=192.0.2.9 user=alice"
    )
    assert event.evidence["source_ip"] == "192.0.2.9"
    assert event.evidence["process"] == "sudo"
    assert event.evidence["pid"] == 1234
    assert [signal.code for signal in Detector().score(event, []).signals] == ["log.auth_failure"]
    ambiguous = parse_log_line(
        "sudo: pam_unix(sudo:auth): authentication failure; "
        "rhost=192.0.2.9 rhost=192.0.2.8 user=alice"
    )
    assert ambiguous.source_ip is None


CLEAN = [
    "scan completed, no malware found",
    "malware scanner started",
    "reading /docs/malware/guide.txt",
    "user malware logged in",
    "clamd[22]: /tmp/safe: OK",
    "clamscan: Infected files: 0",
]
ATTACK = [
    "clamd[22]: /tmp/payload: Win.Trojan.Sample FOUND",
    "/tmp/eicar: Eicar-Signature FOUND",
]


def test_clean_and_attack_corpora_have_separate_false_positive_and_miss_counts():
    false_positives = sum(Detector().score(log(line), []).score >= 70 for line in CLEAN)
    misses = sum(Detector().score(log(line), []).score < 70 for line in ATTACK)
    assert (false_positives, misses) == (0, 0)
    infected = log(ATTACK[0])
    assert infected.evidence["file"] == "/tmp/payload"
    assert infected.evidence["signature"] == "Win.Trojan.Sample"
    assert infected.evidence["result"] == "found"


def failures(offsets):
    return [
        log(
            f"{(NOW - timedelta(seconds=offset)).isoformat()} host sshd[22]: "
            "Failed password for alice from 192.0.2.9 port 42 ssh2"
        )
        for offset in offsets
    ]


def test_backlogged_hourly_failures_are_not_burst():
    events = failures([3600 * i for i in range(6)])
    assert all(Detector().score(event, events).score == 25 for event in events)


def test_reverse_arrival_burst_and_window_width():
    events = failures([250, 200, 150, 100, 50, 0])
    assert Detector().score(events[0], events[1:]).score == 100
    assert Detector().score(events[-1], events[:-1]).score == 100
    # All six source timestamps were collected after the complete interval.
    wide = [
        event.model_copy(update={"collected_at": NOW + timedelta(minutes=10)})
        for event in failures([0, 100, 200, -100, -200, -300])
    ]
    assert Detector().score(wide[0], wide[1:]).score == 25


def test_future_clock_falls_back_and_old_clock_is_labeled():
    future = failures([-3600])[0]
    assert correlation_time(future) == NOW
    assert correlation_basis(future) == "future_source_fallback"
    assert correlation_basis(failures([3600])[0]) == "delayed_source"


def test_success_after_failures_is_account_asset_and_actor_scoped():
    recent = failures([250, 200, 150, 100, 50, 10])
    success = log(
        "2026-09-26T12:00:00Z host sshd[22]: Accepted password "
        "for alice from 192.0.2.9 port 42 ssh2"
    )
    assert success.event_type == "log.auth_success"
    assert success.target == "host"
    assert Detector().score(success, recent).score == 60
    for field, value in [("user", "bob"), ("asset", "other-host"), ("actor_ip", "192.0.2.10")]:
        other = success.model_copy(update={"evidence": {**success.evidence, field: value}})
        assert Detector().score(other, recent).score == 0


def test_maximum_port_changes_preserve_both_directions():
    event = SecurityEvent(
        source="port_scan",
        event_type="port_scan.result",
        title="Ports",
        summary="Ports",
        evidence={"newly_opened": list(range(1, 513)), "newly_closed": list(range(513, 1025))},
    )
    result = Detector().score(event, [])
    assert {"port.newly_opened", "port.closed"} <= {signal.code for signal in result.signals}
    assert all(len(signal.detail) <= 500 for signal in result.signals)
    assert len(event.evidence["newly_opened"]) + len(event.evidence["newly_closed"]) == 1024
    for direction in ("newly_opened", "newly_closed"):
        changed = event.model_copy(update={"evidence": {direction: list(range(1, 1025))}})
        assert Detector().score(changed, []).signals


def test_replay_is_deterministic_read_only_and_explains_missing_evidence():
    events = failures([250, 200, 150, 100, 50, 0])
    original = [item.model_dump_json() for item in events]
    policy = RuleConfig(auth_failure_count=3)
    first = replay_events(events, policy)
    second = replay_events(list(reversed(events)), policy)
    assert first == second
    assert first.candidate_alert_count == 4
    assert first.added_candidates
    assert first.limitations
    assert [item.model_dump_json() for item in events] == original
    assert first.candidate_fingerprint == policy.fingerprint


def test_confirmed_service_failures_score_independently_of_ping():
    failed = SecurityEvent(
        source="system",
        event_type="service.failed",
        title="Service",
        summary="Service",
        evidence={"confirmed": True},
    )
    assert Detector().score(failed, []).severity is Severity.HIGH
    assert (
        Detector().score(failed.model_copy(update={"evidence": {"confirmed": False}}), []).score
        == 0
    )


def test_index_matches_real_window_thresholds_after_shuffled_arrivals():
    import random

    from socketclaw.detection import CorrelationIndex

    events = failures(list(range(-240, 721, 20)))
    random.Random(83).shuffle(events)
    config = RuleConfig()
    index = CorrelationIndex(config)
    history = []
    for event in events:
        expected = Detector(config).score(event, history)
        actual = Detector(config).score(event, index)
        assert actual.score == expected.score
        assert {item.code for item in actual.signals} == {item.code for item in expected.signals}
        history.append(event)
        index.append(event)
    # Inserting the same candidate twice must not inflate the numeric history.
    before = index.count(events[0], Detector().window, "auth", limit=10000)
    index.append(events[1])
    assert index.count(events[0], Detector().window, "auth", limit=10000) == before


def test_index_excludes_other_rule_account_asset_and_actor():
    from uuid import uuid4

    from socketclaw.detection import CorrelationIndex

    version = uuid4()
    samples = [event.model_copy(update={"rule_version": version}) for event in failures([5] * 5)]
    current = failures([0])[0].model_copy(update={"rule_version": version})
    index = CorrelationIndex(RuleConfig(), samples)
    assert Detector().score(current, index).score == 100
    assert Detector().score(current.model_copy(update={"rule_version": uuid4()}), index).score == 25
    for field, value in [("user", "other"), ("asset", "other"), ("actor_ip", "192.0.2.99")]:
        other = current.model_copy(update={"evidence": {**current.evidence, field: value}})
        assert Detector().score(other, index).score == 25


def test_numeric_index_does_not_rescan_retained_event_objects(monkeypatch):
    import socketclaw.detection as detection

    events = failures([10] * 3000)
    index = detection.CorrelationIndex(RuleConfig(), events)
    calls = 0
    original = detection.correlation_time

    def measured(event):
        nonlocal calls
        calls += 1
        return original(event)

    monkeypatch.setattr(detection, "correlation_time", measured)
    for event in failures([0] * 1000):
        assert Detector().score(event, index).score == 100
        index.append(event)
    assert calls < 10000


def test_explicit_local_exposure_violation_retains_process_evidence():
    violation = {
        "port": 8080,
        "binding_address": "*",
        "pid": 123,
        "process": "python",
        "path": "/usr/bin/python",
        "allowed_exposure": "loopback",
    }
    event = SecurityEvent(
        source="port_scan",
        event_type="port_scan.result",
        title="Ports",
        summary="Ports",
        evidence={"exposure_violations": [violation]},
    )
    result = Detector().score(event, [])
    assert result.score == 55
    assert result.signals[0].code == "port.unexpected_exposure"
    assert "internet reachability is unknown" in result.signals[0].detail
    assert event.evidence["exposure_violations"] == [violation]


@pytest.mark.parametrize("character", ["문", "😀"])
async def test_multibyte_context_checkpoint_roundtrip_is_byte_bounded(tmp_path, character):
    import json

    from socketclaw.probes.logs import LogProbe, _probe_id
    from socketclaw.storage import Repository

    path = tmp_path / "auth.log"
    path.write_text("")
    repository = Repository(tmp_path / "context.db")
    await repository.initialize()
    try:
        probe = LogProbe([path], repository=repository)
        await repository.ingest_batch(await probe.collect(), Detector())
        line = character * 4000
        path.write_text((line + "\n") * 3)
        batch = await probe.collect()
        serialized = json.dumps(batch.checkpoints[0].state, separators=(",", ":")).encode()
        assert len(serialized) < 64 * 1024
        await repository.ingest_batch(batch, Detector())
        state = (await repository.load_checkpoint(_probe_id(path))).state
        assert len(state["context_before"]) == 3
        source_keys = [item["source_key"] for item in state["context_before"]]
        for item in state["context_before"]:
            evidence = item["evidence"]
            assert len(evidence["message"].encode("utf-8")) <= 1024
            assert evidence["original_byte_length"] == len(line.encode("utf-8"))
            assert evidence["context_truncated"] is True
        with path.open("a") as stream:
            stream.write("Failed password for alice from 192.0.2.9\n")
        following = await LogProbe([path], repository=repository).collect()
        assert [item.source_key for item in following.observations[:3]] == source_keys
        await repository.ingest_batch(following, Detector())
        assert (
            following.observations[3].evidence["message"]
            == "Failed password for alice from 192.0.2.9"
        )
        assert "context_truncated" not in following.observations[3].evidence
    finally:
        await repository.close()


@pytest.mark.parametrize("pid", ["1" * 5000, "9999999999", "0"])
def test_malformed_process_identifier_remains_unknown_without_blocking_parser(pid):
    parsed = parse_log_line(f"sudo[{pid}]: alice : TTY=pts/0 ; USER=root ; COMMAND=/bin/id")
    assert parsed.pid is None
    assert parsed.parse_quality == "partial"
    assert parsed.action == "sudo_execution"
    assert parsed.command == "/bin/id"


async def test_malformed_pid_line_does_not_block_following_log_observation(tmp_path):
    from socketclaw.probes.logs import LogProbe

    path = tmp_path / "auth.log"
    path.write_text("")
    probe = LogProbe([path])
    await probe.poll()
    path.write_text(
        "sudo[" + "1" * 5000 + "]: alice : USER=root ; COMMAND=/bin/id\n"
        "sshd[42]: Failed password for alice from 192.0.2.9\n"
    )
    observed = await probe.poll()
    assert [item.event_type for item in observed] == ["log.sudo_execution", "log.auth_failure"]
    assert observed[0].evidence["pid"] is None
    assert observed[1].evidence["pid"] == 42
    assert await probe.poll() == []
