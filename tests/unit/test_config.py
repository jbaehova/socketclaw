from __future__ import annotations

import stat
from pathlib import Path

import pytest
from pydantic import ValidationError

from socketclaw.config import AppConfig, ConfigError, ConfigStore


def test_configuration_is_pinned_to_luna_with_adaptive_reasoning() -> None:
    config = AppConfig()

    assert config.model == "luna"
    assert config.preset.model_id == "gpt-5.6-luna"
    assert config.preset.effort_for("medium") == "medium"
    assert config.preset.effort_for("high") == "high"
    assert config.preset.effort_for("critical") == "high"


def test_previous_persisted_model_selection_migrates_to_luna(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.ensure_home()
    store.config_path.write_text('model = "previous-model"\n')

    config = store.load()

    assert config.model == "luna"
    assert config.preset.model_id == "gpt-5.6-luna"


def test_unknown_model_is_rejected() -> None:
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"model": "unknown-provider-model"})


def test_secret_is_written_to_private_env_file(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)

    store.save_api_key("sk-proj-test")

    assert store.env_path.read_text() == "OPENAI_API_KEY=sk-proj-test\n"
    assert stat.S_IMODE(store.env_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700


def test_secret_round_trip_preserves_shell_metacharacters_as_data(
    tmp_path: Path,
) -> None:
    store = ConfigStore(tmp_path)
    secret = "sk-proj-test # spaces ' quotes $HOME"

    store.save_api_key(secret)

    assert store.load_api_key() == secret
    assert "$HOME" in store.env_path.read_text()


def test_saving_secret_corrects_existing_permissions(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.ensure_home()
    store.env_path.write_text("OPENAI_API_KEY=old\n")
    store.env_path.chmod(0o644)

    store.save_api_key("sk-proj-new")

    assert stat.S_IMODE(store.env_path.stat().st_mode) == 0o600


def test_config_round_trip_is_atomic_and_validated(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    expected = AppConfig(
        model="luna",
        targets=["1.1.1.1", "example.com"],
        ping_interval=8.5,
        scan_interval=90,
        ports=[22, 443, 8443],
        log_paths=["/var/log/system.log"],
        investigation_threshold="medium",
        response_mode="simulation",
        theme="nord",
    )

    store.save(expected)

    assert store.load() == expected
    assert not list(tmp_path.glob("*.tmp"))
    assert stat.S_IMODE(store.config_path.stat().st_mode) == 0o600


def test_missing_config_returns_defaults(tmp_path: Path) -> None:
    assert ConfigStore(tmp_path).load() == AppConfig()


def test_socketclaw_home_environment_selects_storage_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOCKETCLAW_HOME", str(tmp_path))

    store = ConfigStore()

    assert store.home == tmp_path
    assert store.env_path == tmp_path / ".env"
    assert store.config_path == tmp_path / "config.toml"
    assert store.database_path == tmp_path / "socketclaw.db"


@pytest.mark.parametrize(
    "target",
    ["", "https://example.com", "host with spaces", "example.com/path", "-bad.example"],
)
def test_invalid_target_is_rejected(target: str) -> None:
    with pytest.raises(ValidationError):
        AppConfig(targets=[target])


@pytest.mark.parametrize("port", [0, 65536, -1])
def test_invalid_port_is_rejected(port: int) -> None:
    with pytest.raises(ValidationError):
        AppConfig(ports=[port])


def test_duplicate_ports_are_normalized_in_input_order() -> None:
    assert AppConfig(ports=[443, 22, 443, 80, 22]).ports == [443, 22, 80]


def test_corrupt_toml_has_actionable_error(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.ensure_home()
    store.config_path.write_text('model = "terra"\ntargets = [')

    with pytest.raises(ConfigError, match=r"Cannot read config\.toml"):
        store.load()


def test_malformed_env_file_has_actionable_error(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.ensure_home()
    store.env_path.write_text("OPENAI_API_KEY='unterminated\n")

    with pytest.raises(ConfigError, match=r"Cannot read \.env"):
        store.load_api_key()


@pytest.mark.parametrize("secret", ["", "line1\nline2", "nul\x00value"])
def test_invalid_secret_is_rejected_without_writing(
    tmp_path: Path,
    secret: str,
) -> None:
    store = ConfigStore(tmp_path)

    with pytest.raises(ConfigError, match="OpenAI API key"):
        store.save_api_key(secret)

    assert not store.env_path.exists()
