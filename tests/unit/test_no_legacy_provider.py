from __future__ import annotations

import importlib.metadata
import tomllib
from pathlib import Path

from packaging.requirements import Requirement

FORBIDDEN_DEPENDENCIES = {
    "gradio",
    "langchain-anthropic",
    "langchain-core",
    "langgraph",
    "websockets",
}
FORBIDDEN_TOP_LEVEL_PACKAGES = {
    "agent",
    "network",
    "probes",
    "protocol",
    "storage",
    "ui",
}


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

    assert packages.isdisjoint(FORBIDDEN_TOP_LEVEL_PACKAGES)
