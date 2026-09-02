"""Validated local configuration and private OpenAI credentials."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

ModelKey = Literal["luna"]
ReasoningEffort = Literal["medium", "high"]
InvestigationThreshold = Literal["medium", "high", "critical"]
ResponseMode = Literal["simulation", "approval", "automatic"]


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


class AppConfig(BaseModel):
    """All non-secret SocketClaw settings."""

    model_config = ConfigDict(extra="forbid")

    model: ModelKey = "luna"
    targets: list[str] = Field(default_factory=lambda: ["1.1.1.1"])
    ping_interval: float = Field(default=5.0, ge=1.0, le=3600.0)
    scan_interval: float = Field(default=60.0, ge=5.0, le=86400.0)
    ports: list[int] = Field(default_factory=lambda: [22, 53, 80, 443, 3389, 5432, 6379, 8080])
    log_paths: list[str] = Field(default_factory=list)
    investigation_threshold: InvestigationThreshold = "high"
    response_mode: ResponseMode = "approval"
    theme: str = Field(default="textual-dark", min_length=1, max_length=80)

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("at least one monitoring target is required")
        normalized: list[str] = []
        for candidate in values:
            target = candidate.strip()
            if not _is_host_or_address(target):
                raise ValueError(f"invalid monitoring target: {candidate!r}")
            if target not in normalized:
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
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))

    @field_validator("theme")
    @classmethod
    def normalize_theme(cls, value: str) -> str:
        return value.strip()

    @property
    def preset(self) -> ModelPreset:
        """Return the fixed OpenAI model contract."""
        return OPENAI_MODEL


class ConfigStore:
    """Read and atomically write SocketClaw files below its private home."""

    def __init__(self, home: Path | None = None) -> None:
        selected = home
        if selected is None:
            configured_home = os.getenv("SOCKETCLAW_HOME")
            selected = (
                Path(configured_home).expanduser()
                if configured_home
                else Path.home() / ".socketclaw"
            )
        self.home = Path(selected).expanduser()
        self.env_path = self.home / ".env"
        self.config_path = self.home / "config.toml"
        self.database_path = self.home / "socketclaw.db"

    def ensure_home(self) -> None:
        """Create the application directory and enforce private permissions."""
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.home.chmod(0o700)

    def load(self) -> AppConfig:
        """Load validated non-secret settings, or defaults on first run."""
        if not self.config_path.exists():
            return AppConfig()
        try:
            data = tomllib.loads(self.config_path.read_text(encoding="utf-8"))
            if isinstance(data.get("model"), str) and data["model"] != "luna":
                data["model"] = "luna"
            return AppConfig.model_validate(data)
        except (OSError, tomllib.TOMLDecodeError, ValidationError, TypeError) as exc:
            raise ConfigError(f"Cannot read config.toml: {exc}") from exc

    def save(self, config: AppConfig) -> None:
        """Persist validated settings with an atomic private-file replace."""
        validated = AppConfig.model_validate(config)
        self._atomic_write(self.config_path, _config_as_toml(validated))

    def load_api_key(self) -> str | None:
        """Read the OpenAI key without executing the env file."""
        if not self.env_path.exists():
            return None
        try:
            for raw_line in self.env_path.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                fields = shlex.split(line, comments=False, posix=True)
                if len(fields) != 1 or "=" not in fields[0]:
                    raise ValueError("expected NAME=value")
                name, value = fields[0].split("=", 1)
                if name == "OPENAI_API_KEY":
                    return value or None
            return None
        except (OSError, ValueError) as exc:
            raise ConfigError(f"Cannot read .env: {exc}") from exc

    def save_api_key(self, value: str) -> None:
        """Store an OpenAI key as inert env-file data."""
        if not value.strip() or "\n" in value or "\r" in value or "\x00" in value:
            raise ConfigError("OpenAI API key must be one non-empty line")
        content = f"OPENAI_API_KEY={shlex.quote(value)}\n"
        self._atomic_write(self.env_path, content)

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
                temporary.write(content)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_path = Path(temporary.name)
            temporary_path.chmod(0o600)
            os.replace(temporary_path, destination)
            destination.chmod(0o600)
        except OSError as exc:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            raise ConfigError(f"Cannot write {destination.name}: {exc}") from exc


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


def _config_as_toml(config: AppConfig) -> str:
    values: dict[str, Any] = config.model_dump(mode="json")
    lines = [
        f"model = {json.dumps(values['model'])}",
        f"targets = {json.dumps(values['targets'])}",
        f"ping_interval = {values['ping_interval']}",
        f"scan_interval = {values['scan_interval']}",
        f"ports = {json.dumps(values['ports'])}",
        f"log_paths = {json.dumps(values['log_paths'])}",
        f"investigation_threshold = {json.dumps(values['investigation_threshold'])}",
        f"response_mode = {json.dumps(values['response_mode'])}",
        f"theme = {json.dumps(values['theme'])}",
    ]
    return "\n".join(lines) + "\n"
