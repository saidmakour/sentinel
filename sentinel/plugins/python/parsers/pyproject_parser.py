from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_parser import BaseParser


class PyProjectParser(BaseParser):
    """
    Parse Python pyproject.toml files.
    Supports PEP 621 and Poetry dependencies.
    """

    FILE = "pyproject.toml"
    PRIORITY = DependencySourcePriority.MANIFEST

    def supports(
        self,
        project_path: Path,
    ) -> bool:

        return (project_path / self.FILE).exists()

    def parse(
        self,
        project_path: Path,
    ) -> list[ScannedDependency]:

        file = project_path / self.FILE

        with file.open("rb") as f:
            data = tomllib.load(f)

        dependencies: dict[str, ScannedDependency] = {}
        self._parse_project_dependencies(
            data,
            dependencies,
        )

        self._parse_poetry_dependencies(
            data,
            dependencies,
        )

        return list(dependencies.values())

    def _parse_project_dependencies(
        self,
        data: dict[str, Any],
        dependencies: dict[str, ScannedDependency],
    ):

        project = data.get("project", {})

        for requirement in project.get(
            "dependencies",
            [],
        ):
            dependency = self._parse_requirement(requirement)

            if dependency:
                dependencies.setdefault(
                    dependency.name.lower(),
                    dependency,
                )

    def _parse_poetry_dependencies(
        self,
        data: dict[str, Any],
        dependencies: dict[str, ScannedDependency],
    ):

        poetry = data.get("tool", {}).get("poetry", {})

        poetry_dependencies = poetry.get("dependencies", {})

        for name, version in poetry_dependencies.items():
            # Ignore Python interpreter
            if name.lower() == "python":
                continue

            dependencies.setdefault(
                name.lower(),
                ScannedDependency(
                    name=name,
                    version=self._clean_version(version),
                    ecosystem=Ecosystem.PYPI,
                    source=self.FILE,
                    priority=self.PRIORITY,
                ),
            )

    def _parse_requirement(
        self,
        requirement: str,
    ) -> ScannedDependency | None:

        for separator in (
            "==",
            ">=",
            "<=",
            "~=",
            "^",
        ):
            if separator in requirement:
                name, version = requirement.split(
                    separator,
                    1,
                )

                return ScannedDependency(
                    name=name.strip(),
                    version=version.strip(),
                    ecosystem=Ecosystem.PYPI,
                    source=self.FILE,
                    priority=self.PRIORITY,
                )

        return ScannedDependency(
            name=requirement.strip(),
            version="unknown",
            ecosystem=Ecosystem.PYPI,
            source=self.FILE,
            priority=self.PRIORITY,
        )

    def _clean_version(
        self,
        version: str | dict[str, Any] | None,
    ) -> str:

        if isinstance(version, str):
            return version

        if isinstance(version, dict):
            return str(
                version.get(
                    "version",
                    "unknown",
                )
            )

        return "unknown"
