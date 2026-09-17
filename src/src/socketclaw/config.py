"""Validated local configuration and private OpenAI credentials."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import stat
import tempfile
import tomllib
import unicodedata
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .rules import RuleConfig

ModelKey = Literal["luna"]
ReasoningEffort = Literal["medium", "high"]
Port = Annotated[int, Field(strict=True, ge=1, le=65535)]
LogPath = Annotated[str, Field(max_length=4096)]
_MANAGED_FILE_MAX_BYTES = 1024 * 1024


class ConfigError(RuntimeError):
    """Configuration or secret storage could not be read or written safely."""


@dataclass(frozen=True, slots=True)
class ModelPreset:
    """The fixed OpenAI model and its severity-aware reasoning policy."""

    key: ModelKey
    label: str
    model_id: str
    default_effort: ReasoningEffort
    elevated_effort: ReasoningEffort

    def effort_for(self, severity: str) -> ReasoningEffort:
        """Spend more reasoning on high-impact security events."""
        return self.elevated_effort if severity in {"high", "critical"} else self.default_effort

    @property
    def reasoning_label(self) -> str:
        """Return the compact policy label shown in the UI."""
        return f"{self.default_effort.upper()}-{self.elevated_effort.upper()}"


OPENAI_MODEL = ModelPreset(
    key="luna",
    label="GPT-5.6 Luna",
    model_id="gpt-5.6-luna",
    default_effort="medium",
    elevated_effort="high",
)

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class AppConfig(BaseModel):
    """All non-secret SocketClaw settings."""

    model_config = ConfigDict(extra="forbid", revalidate_instances="always")

    rules: RuleConfig = Field(default_factory=RuleConfig)
    model: ModelKey = "luna"
    targets: list[str] = Field(default_factory=lambda: ["1.1.1.1"], max_length=256)
    ping_interval: float = Field(default=5.0, ge=1.0, le=3600.0)
    scan_interval: float = Field(default=60.0, ge=5.0, le=86400.0)
    port_baseline_ttl: float = Field(default=86400.0, ge=1.0, le=2592000.0)
    ports: list[Port] = Field(
        default_factory=lambda: [22, 53, 80, 443, 3389, 5432, 6379, 8080],
        max_length=1024,
    )
    log_paths: list[LogPath] = Field(default_factory=list, max_length=256)
    theme: str = Field(default="textual-dark", min_length=1, max_length=80)

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("at least one monitoring target is required")
        normalized: list[str] = []
        seen: set[str] = set()
        for candidate in values:
            target = candidate.strip()
            if not _is_host_or_address(target):
                raise ValueError(f"invalid monitoring target: {candidate!r}")
            identity = _target_identity(target)
            if identity not in seen:
                seen.add(identity)
                normalized.append(target)
        return normalized

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, values: list[int]) -> list[int]:
        if not values:
            raise ValueError("at least one TCP port is required")
        normalized: list[int] = []
        for port in values:
            if not 1 <= port <= 65535:
                raise ValueError(f"invalid TCP port: {port}")
            if port not in normalized:
                normalized.append(port)
        return normalized

    @field_validator("log_paths")
    @classmethod
    def normalize_log_paths(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            path = value.strip()
            if not path:
                continue
            if _has_control_characters(path):
                raise ValueError("log paths cannot contain control characters")
            if path not in normalized:
                normalized.append(path)
        return normalized

    @field_validator("theme")
    @classmethod
    def normalize_theme(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("theme must not be blank")
        if _has_control_characters(normalized):
            raise ValueError("theme cannot contain control characters")
        return normalized

    @field_validator("ping_interval", "scan_interval", "port_baseline_ttl", mode="before")
    @classmethod
    def reject_boolean_intervals(cls, value: object) -> object:
        if isinstance(value, bool):
            raise ValueError("interval must be a number, not a boolean")
        return value

    @property
    def preset(self) -> ModelPreset:
        """Return the fixed OpenAI model contract."""
        return OPENAI_MODEL


class ConfigStore:
    """Read and atomically write SocketClaw files below its private home."""

    def __init__(self, home: Path | None = None) -> None:
        try:
            selected = home
            if selected is None:
                configured_home = os.getenv("SOCKETCLAW_HOME")
                selected = (
                    Path(configured_home).expanduser()
                    if configured_home
                    else Path.home() / ".socketclaw"
                )
            self.home = Path(selected).expanduser()
        except (OSError, RuntimeError) as exc:
            raise ConfigError(f"Cannot resolve application home: {exc}") from exc
        self.env_path = self.home / ".env"
        self.config_path = self.home / "config.toml"
        self.database_path = self.home / "socketclaw.db"

    def ensure_home(self) -> None:
        """Create the application directory and enforce private permissions."""
        self._validate_home()
        try:
            self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.home.chmod(0o700)
        except OSError as exc:
            raise ConfigError(f"Cannot prepare application home {self.home}: {exc}") from exc

    def load(self) -> AppConfig:
        """Load validated non-secret settings, or defaults on first run."""
        rendered = self._read_private_text(self.config_path)
        if rendered is None:
            return AppConfig()
        try:
            data = tomllib.loads(rendered)
            if isinstance(data.get("model"), str) and data["model"] != "luna":
                data["model"] = "luna"
            # These settings were persisted before they had runtime semantics.
            # Accept old files while keeping the active configuration contract honest.
            data.pop("investigation_threshold", None)
            data.pop("response_mode", None)
            return AppConfig.model_validate(data)
        except (
            OSError,
            UnicodeError,
            tomllib.TOMLDecodeError,
            ValidationError,
            TypeError,
        ) as exc:
            raise ConfigError(f"Cannot read config.toml: {exc}") from exc

    def save(self, config: AppConfig) -> None:
        """Persist validated settings with an atomic private-file replace."""
        validated = AppConfig.model_validate(config)
        self._atomic_write(self.config_path, _config_as_toml(validated))

    def load_api_key(self) -> str | None:
        """Read the OpenAI key without executing the env file."""
        rendered = self._read_private_text(self.env_path)
        if rendered is None:
            return None
        try:
            api_key: str | None = None
            found_api_key = False
            for raw_line in rendered.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                fields = shlex.split(line, comments=False, posix=True)
                if len(fields) != 1 or "=" not in fields[0]:
                    raise ValueError("expected NAME=value")
                name, value = fields[0].split("=", 1)
                if not _ENV_NAME.fullmatch(name):
                    raise ValueError("invalid environment variable name")
                if name == "OPENAI_API_KEY":
                    if found_api_key:
                        raise ValueError("OPENAI_API_KEY is defined more than once")
                    if _has_control_characters(value):
                        raise ValueError("OPENAI_API_KEY contains control characters")
                    api_key = value.strip() or None
                    found_api_key = True
            return api_key
        except (OSError, ValueError) as exc:
            raise ConfigError(f"Cannot read .env: {exc}") from exc

    def save_api_key(self, value: str) -> None:
        """Store an OpenAI key as inert env-file data."""
        normalized = value.strip()
        if not normalized or _has_control_characters(value):
            raise ConfigError("OpenAI API key must be one non-empty line")
        content = f"OPENAI_API_KEY={shlex.quote(normalized)}\n"
        self._atomic_write(self.env_path, content)

    def clear_api_key(self) -> None:
        """Remove only SocketClaw's managed credential file, if it exists."""
        self._validate_home()
        try:
            self.env_path.unlink(missing_ok=True)
        except OSError as exc:
            raise ConfigError(f"Cannot remove .env: {exc}") from exc

    def _read_private_text(self, path: Path) -> str | None:
        """Read one managed regular file without following links or loose modes."""
        self._validate_home()
        name = path.name
        fd: int | None = None
        try:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ConfigError(f"Cannot read {name}: symbolic links are not allowed")
            if not stat.S_ISREG(metadata.st_mode):
                raise ConfigError(f"Cannot read {name}: expected a regular file")
            if metadata.st_nlink != 1:
                raise ConfigError(f"Cannot read {name}: hard links are not allowed")
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                raise ConfigError(f"Cannot read {name}: expected a regular file")
            if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
                raise ConfigError(f"Cannot read {name}: file changed while opening")
            if opened.st_nlink != 1:
                raise ConfigError(f"Cannot read {name}: hard links are not allowed")
            if opened.st_size > _MANAGED_FILE_MAX_BYTES:
                raise ConfigError(
                    f"Cannot read {name}: managed file exceeds {_MANAGED_FILE_MAX_BYTES} bytes"
                )
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            stream = os.fdopen(fd, encoding="utf-8")
            fd = None
            with stream:
                rendered = stream.read(_MANAGED_FILE_MAX_BYTES + 1)
                if len(rendered.encode("utf-8")) > _MANAGED_FILE_MAX_BYTES:
                    raise ConfigError(
                        f"Cannot read {name}: managed file exceeds {_MANAGED_FILE_MAX_BYTES} bytes"
                    )
                return rendered
        except FileNotFoundError:
            return None
        except ConfigError:
            raise
        except UnicodeError as exc:
            raise ConfigError(f"Cannot read {name}: file is not valid UTF-8") from exc
        except OSError as exc:
            raise ConfigError(f"Cannot read {name}: {exc}") from exc
        finally:
            if fd is not None:
                with suppress(OSError):
                    os.close(fd)

    def _validate_home(self) -> None:
        """Reject root, broad, or directly linked homes before filesystem access."""
        try:
            absolute = Path(os.path.abspath(self.home))
            resolved = absolute.resolve(strict=False)
            root = Path(resolved.anchor)
            if resolved == root:
                raise ConfigError("SocketClaw home cannot be a filesystem root")
            broad_homes = {
                Path.home().resolve(strict=False),
                Path(tempfile.gettempdir()).resolve(strict=False),
            }
            if os.name == "posix":
                broad_homes.update(
                    Path(candidate).resolve(strict=False)
                    for candidate in ("/tmp", "/var/tmp", "/usr/tmp")  # nosec B108
                )
            if resolved in broad_homes:
                raise ConfigError(
                    f"SocketClaw home must be a dedicated application directory, not {resolved}"
                )
            direct_path = absolute.parent.resolve(strict=False) / absolute.name
            if absolute.is_symlink() or resolved != direct_path:
                raise ConfigError("SocketClaw home cannot be a symbolic link")
            _reject_untrusted_symlink_ancestors(absolute)
        except ConfigError:
            raise
        except (OSError, RuntimeError) as exc:
            raise ConfigError(f"Cannot validate application home {self.home}: {exc}") from exc

    def _atomic_write(self, destination: Path, content: str) -> None:
        self.ensure_home()
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.home,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                if hasattr(os, "fchmod"):
                    os.fchmod(temporary.fileno(), 0o600)
                temporary.write(content)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_path, destination)
        except (OSError, UnicodeError) as exc:
            raise ConfigError(f"Cannot write {destination.name}: {exc}") from exc
        finally:
            if temporary_path is not None:
                with suppress(OSError):
                    temporary_path.unlink(missing_ok=True)


def _reject_untrusted_symlink_ancestors(path: Path) -> None:
    """Allow only root-owned platform aliases such as macOS /var."""
    root = Path(path.anchor)
    candidate = path.parent
    while candidate != root:
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            candidate = candidate.parent
            continue
        if stat.S_ISLNK(metadata.st_mode):
            trusted_root_alias = (
                os.name == "posix"
                and candidate.parent == root
                and metadata.st_uid == 0
                and candidate.name in {"etc", "tmp", "var"}
            )
            if not trusted_root_alias:
                raise ConfigError(
                    f"SocketClaw home ancestor cannot be a symbolic link: {candidate}"
                )
        candidate = candidate.parent


def _is_host_or_address(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    labels = value.removesuffix(".").split(".")
    return all(_HOST_LABEL.fullmatch(label) for label in labels)


def _target_identity(value: str) -> str:
    """Return a comparison key without changing the operator's display value."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value.casefold()


def _has_control_characters(value: str) -> bool:
    return any(
        ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or unicodedata.category(character) == "Cf"
        for character in value
    )


def _config_as_toml(config: AppConfig) -> str:
    values: dict[str, Any] = config.model_dump(mode="json")
    lines = [
        f"model = {_toml_value(values['model'])}",
        f"targets = {_toml_value(values['targets'])}",
        f"ping_interval = {values['ping_interval']}",
        f"scan_interval = {values['scan_interval']}",
        f"port_baseline_ttl = {values['port_baseline_ttl']}",
        f"ports = {_toml_value(values['ports'])}",
        f"log_paths = {_toml_value(values['log_paths'])}",
        f"theme = {_toml_value(values['theme'])}",
    ]
    lines.extend(["", "[rules]"])
    lines.extend(
        f"{key} = {_toml_value(value)}" for key, value in values["rules"].items() if key != "points"
    )
    lines.extend(["", "[rules.points]"])
    lines.extend(f"{key} = {value}" for key, value in values["rules"]["points"].items())
    return "\n".join(lines) + "\n"


def _toml_value(value: object) -> str:
    """Encode the JSON-compatible subset shared by SocketClaw's flat TOML file."""
    return json.dumps(value, ensure_ascii=False)
