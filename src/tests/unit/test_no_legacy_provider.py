from __future__ import annotations

import importlib.metadata
import tomllib
from pathlib import Path

from packaging.requirements import Requirement

import socketclaw

FORBIDDEN_DEPENDENCIES = {
    "anthropic",
    "claude-agent-sdk",
    "gradio",
    "langchain-anthropic",
    "langchain-core",
    "langchain-openrouter",
    "langgraph",
    "openrouter",
    "websockets",
}
FORBIDDEN_PROVIDER_MARKERS = ("openrouter", "anthropic", "claude")
FORBIDDEN_TOP_LEVEL_PACKAGES = {
    "agent",
    "network",
    "probes",
    "protocol",
    "storage",
    "ui",
}
DIRECT_RUNTIME_DEPENDENCIES = {
    "aiosqlite",
    "anyio",
    "click",
    "httpx",
    "pydantic",
    "sqlalchemy",
    "textual",
    "typer",
}


def test_direct_runtime_dependencies_are_declared() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text())
    names = {
        Requirement(value).name.casefold() for value in project["project"].get("dependencies", [])
    }

    assert names == DIRECT_RUNTIME_DEPENDENCIES


def test_package_version_has_one_authoritative_source() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text())

    assert project["project"].get("dynamic") == ["version"]
    assert "version" not in project["project"]
    assert project["tool"]["hatch"]["version"]["path"] == "src/socketclaw/__init__.py"
    assert importlib.metadata.version("socketclaw") == socketclaw.__version__


def test_project_declares_no_legacy_runtime_or_development_dependency() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text())
    declarations = list(project["project"].get("dependencies", []))
    for group in project.get("dependency-groups", {}).values():
        declarations.extend(group)
    names = {Requirement(value).name.casefold() for value in declarations}

    assert names.isdisjoint(FORBIDDEN_DEPENDENCIES)


def test_installed_socketclaw_metadata_has_no_legacy_dependency() -> None:
    requirements = importlib.metadata.requires("socketclaw") or []
    names = {Requirement(value).name.casefold() for value in requirements}

    assert names.isdisjoint(FORBIDDEN_DEPENDENCIES)


def test_source_tree_exposes_only_the_socketclaw_product_package() -> None:
    packages = {
        path.name
        for path in Path("src").iterdir()
        if path.is_dir() and (path / "__init__.py").exists()
    }

    assert packages == {"socketclaw"}
    assert packages.isdisjoint(FORBIDDEN_TOP_LEVEL_PACKAGES)
    assert not Path("src/__init__.py").exists()
    assert Path(socketclaw.__file__).with_name("py.typed").is_file()


def test_build_targets_exclude_development_and_generated_files() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text())
    hatch = project["tool"]["hatch"]

    assert hatch["build"]["targets"]["wheel"]["packages"] == ["src/socketclaw"]
    assert set(hatch["build"]["targets"]["sdist"]["include"]) == {
        "/CHANGELOG.md",
        "/README.md",
        "/pyproject.toml",
        "/src/socketclaw",
    }


def test_runtime_source_has_no_alternate_model_provider_path() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(Path("src/socketclaw").rglob("*.py"))
    ).casefold()

    for marker in FORBIDDEN_PROVIDER_MARKERS:
        assert marker not in source
