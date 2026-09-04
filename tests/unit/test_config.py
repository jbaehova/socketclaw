from __future__ import annotations

import os
import stat
import tempfile
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


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits only")
def test_loading_managed_files_corrects_permissive_posix_modes(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.ensure_home()
    store.config_path.write_text('theme = "textual-light"\n')
    store.env_path.write_text("OPENAI_API_KEY=sk-proj-test\n")
    store.config_path.chmod(0o644)
    store.env_path.chmod(0o644)

    assert store.load().theme == "textual-light"
    assert store.load_api_key() == "sk-proj-test"
    assert stat.S_IMODE(store.config_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.env_path.stat().st_mode) == 0o600


@pytest.mark.parametrize("managed_name", ["config.toml", ".env"])
def test_managed_reads_reject_symbolic_links(
    tmp_path: Path,
    managed_name: str,
) -> None:
    store = ConfigStore(tmp_path / "home")
    store.ensure_home()
    outside = tmp_path / "outside"
    outside.write_text("OPENAI_API_KEY=do-not-read\n")
    (store.home / managed_name).symlink_to(outside)

    read = store.load if managed_name == "config.toml" else store.load_api_key
    with pytest.raises(ConfigError, match="symbolic links are not allowed"):
        read()


@pytest.mark.parametrize("managed_name", ["config.toml", ".env"])
def test_managed_reads_reject_non_regular_files(
    tmp_path: Path,
    managed_name: str,
) -> None:
    store = ConfigStore(tmp_path)
    (store.home / managed_name).mkdir(parents=True)

    read = store.load if managed_name == "config.toml" else store.load_api_key
    with pytest.raises(ConfigError, match="expected a regular file"):
        read()


@pytest.mark.parametrize("managed_name", ["config.toml", ".env"])
def test_managed_reads_reject_hard_links_without_changing_target(
    tmp_path: Path,
    managed_name: str,
) -> None:
    store = ConfigStore(tmp_path / "home")
    store.ensure_home()
    outside = tmp_path / "outside"
    outside.write_text("OPENAI_API_KEY=do-not-read\n")
    outside.chmod(0o644)
    (store.home / managed_name).hardlink_to(outside)

    read = store.load if managed_name == "config.toml" else store.load_api_key
    with pytest.raises(ConfigError, match="hard links are not allowed"):
        read()

    assert outside.read_text() == "OPENAI_API_KEY=do-not-read\n"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644


@pytest.mark.parametrize("managed_name", ["config.toml", ".env"])
def test_managed_reads_reject_oversized_files(
    tmp_path: Path,
    managed_name: str,
) -> None:
    store = ConfigStore(tmp_path)
    store.ensure_home()
    (store.home / managed_name).write_bytes(b"x" * (1024 * 1024 + 1))

    read = store.load if managed_name == "config.toml" else store.load_api_key
    with pytest.raises(ConfigError, match="managed file exceeds"):
        read()


def test_invalid_env_name_does_not_echo_key_shaped_input(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.ensure_home()
    secret = "sk-proj-THIS_SHOULD_NOT_LEAK_123456"
    store.env_path.write_text(f"{secret}=x\n")

    with pytest.raises(ConfigError) as captured:
        store.load_api_key()

    assert secret not in str(captured.value)


def test_clear_api_key_is_idempotent_and_preserves_sibling_files(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.save_api_key("sk-proj-test")
    sibling = tmp_path / "keep.txt"
    sibling.write_text("keep")

    store.clear_api_key()
    store.clear_api_key()

    assert store.load_api_key() is None
    assert sibling.read_text() == "keep"


def test_clear_api_key_refuses_to_remove_a_directory(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.env_path.mkdir(parents=True)

    with pytest.raises(ConfigError, match=r"Cannot remove \.env"):
        store.clear_api_key()

    assert store.env_path.is_dir()


def test_config_round_trip_is_atomic_and_validated(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    expected = AppConfig(
        model="luna",
        targets=["1.1.1.1", "example.com"],
        ping_interval=8.5,
        scan_interval=90,
        ports=[22, 443, 8443],
        log_paths=["/var/log/system.log"],
        theme="nord",
    )

    store.save(expected)

    assert store.load() == expected
    assert not list(tmp_path.glob("*.tmp"))
    assert stat.S_IMODE(store.config_path.stat().st_mode) == 0o600


def test_legacy_inert_settings_are_ignored_and_removed_on_next_save(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.ensure_home()
    store.config_path.write_text(
        'investigation_threshold = "critical"\n'
        'response_mode = "automatic"\n'
        'theme = "textual-light"\n'
    )

    config = store.load()
    store.save(config)

    assert config.theme == "textual-light"
    rendered = store.config_path.read_text()
    assert "investigation_threshold" not in rendered
    assert "response_mode" not in rendered


def test_config_round_trip_preserves_non_bmp_unicode(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    expected = AppConfig(theme="midnight-😀", log_paths=["/tmp/보안.log"])

    store.save(expected)

    assert store.load() == expected


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


def test_unusable_application_home_raises_config_error(tmp_path: Path) -> None:
    home = tmp_path / "not-a-directory"
    home.write_text("occupied")

    with pytest.raises(ConfigError, match="Cannot prepare application home"):
        ConfigStore(home).ensure_home()


def test_filesystem_root_home_is_rejected_before_chmod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    chmod_calls: list[Path] = []
    root = Path(Path.cwd().anchor)
    monkeypatch.setattr(Path, "chmod", lambda path, _mode: chmod_calls.append(path))

    with pytest.raises(ConfigError, match="cannot be a filesystem root"):
        ConfigStore(root).ensure_home()

    assert chmod_calls == []


def test_symbolic_link_home_is_rejected(tmp_path: Path) -> None:
    actual_home = tmp_path / "actual"
    actual_home.mkdir()
    linked_home = tmp_path / "linked"
    linked_home.symlink_to(actual_home, target_is_directory=True)

    with pytest.raises(ConfigError, match="cannot be a symbolic link"):
        ConfigStore(linked_home).ensure_home()


def test_symbolic_link_home_ancestor_is_rejected(tmp_path: Path) -> None:
    actual_parent = tmp_path / "actual"
    actual_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(actual_parent, target_is_directory=True)

    with pytest.raises(ConfigError, match="ancestor cannot be a symbolic link"):
        ConfigStore(linked_parent / "socketclaw").ensure_home()

    assert not (actual_parent / "socketclaw").exists()


def test_home_below_platform_temp_alias_is_allowed() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        home = Path(temporary) / "socketclaw-home"

        ConfigStore(home).ensure_home()

        assert home.is_dir()


@pytest.mark.parametrize(
    "broad_home",
    [Path.home(), Path(tempfile.gettempdir())],
)
def test_broad_existing_home_is_rejected_before_chmod(
    broad_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    chmod_calls: list[Path] = []
    monkeypatch.setattr(Path, "chmod", lambda path, _mode: chmod_calls.append(path))

    with pytest.raises(ConfigError, match="dedicated application directory"):
        ConfigStore(broad_home).ensure_home()

    assert chmod_calls == []


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


def test_equivalent_targets_are_deduplicated_in_input_order() -> None:
    config = AppConfig(
        targets=[
            "EXAMPLE.com",
            "example.COM",
            "2001:0db8::1",
            "2001:db8:0:0:0:0:0:1",
        ]
    )

    assert config.targets == ["EXAMPLE.com", "2001:0db8::1"]


@pytest.mark.parametrize("port", [True, 22.0, "22"])
def test_non_integer_port_is_rejected(port: object) -> None:
    with pytest.raises(ValidationError):
        AppConfig(ports=[port])  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize("field", ["ping_interval", "scan_interval"])
def test_boolean_interval_is_rejected(field: str) -> None:
    with pytest.raises(ValidationError):
        AppConfig.model_validate({field: True})


def test_blank_theme_is_rejected_after_normalization() -> None:
    with pytest.raises(ValidationError, match="theme must not be blank"):
        AppConfig(theme="   ")


def test_theme_control_characters_are_rejected() -> None:
    with pytest.raises(ValidationError, match="theme cannot contain control characters"):
        AppConfig(theme="textual-dark\x1b]0;owned")

    with pytest.raises(ValidationError, match="theme cannot contain control characters"):
        AppConfig(theme="textual-\u202edark")


def test_save_revalidates_constructed_config_instances(tmp_path: Path) -> None:
    invalid = AppConfig.model_construct(targets=[])

    with pytest.raises(ValidationError, match="at least one monitoring target"):
        ConfigStore(tmp_path).save(invalid)


@pytest.mark.parametrize(
    "log_paths",
    [
        ["bad\x00path"],
        ["bad\x1bpath"],
        ["x" * 4097],
        [f"/tmp/log-{index}" for index in range(257)],
    ],
)
def test_unsafe_or_excessive_log_paths_are_rejected(log_paths: list[str]) -> None:
    with pytest.raises(ValidationError):
        AppConfig(log_paths=log_paths)


def test_corrupt_toml_has_actionable_error(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.ensure_home()
    store.config_path.write_text('model = "terra"\ntargets = [')

    with pytest.raises(ConfigError, match=r"Cannot read config\.toml"):
        store.load()


def test_invalid_utf8_config_has_actionable_error(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.ensure_home()
    store.config_path.write_bytes(b"theme = \xff\n")

    with pytest.raises(ConfigError, match=r"Cannot read config\.toml"):
        store.load()


def test_malformed_env_file_has_actionable_error(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.ensure_home()
    store.env_path.write_text("OPENAI_API_KEY='unterminated\n")

    with pytest.raises(ConfigError, match=r"Cannot read \.env"):
        store.load_api_key()


def test_duplicate_api_key_definition_is_rejected(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)
    store.ensure_home()
    store.env_path.write_text("OPENAI_API_KEY=first\nOPENAI_API_KEY=second\n")

    with pytest.raises(ConfigError, match="defined more than once"):
        store.load_api_key()


def test_api_key_surrounding_whitespace_is_trimmed(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)

    store.save_api_key("  sk-proj-test  ")

    assert store.load_api_key() == "sk-proj-test"


@pytest.mark.parametrize(
    "secret",
    [
        "",
        "   ",
        "line1\nline2",
        "nul\x00value",
        "escape\x1bvalue",
        "bidi\u202evalue",
    ],
)
def test_invalid_secret_is_rejected_without_writing(
    tmp_path: Path,
    secret: str,
) -> None:
    store = ConfigStore(tmp_path)

    with pytest.raises(ConfigError, match="OpenAI API key"):
        store.save_api_key(secret)

    assert not store.env_path.exists()


def test_failed_unicode_write_cleans_up_temporary_file(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path)

    with pytest.raises(ConfigError, match=r"Cannot write config\.toml"):
        store._atomic_write(store.config_path, "broken-\ud800")

    assert not store.config_path.exists()
    assert not list(tmp_path.glob("*.tmp"))
