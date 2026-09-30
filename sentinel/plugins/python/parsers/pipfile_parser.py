from __future__ import annotations

from pathlib import Path
from typing import Any

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.scanners.parsers.base_toml_parser import BaseTomlParser


class PipfileParser(BaseTomlParser):
    """
    Parse Pipfile dependencies.
    """

    FILE = "Pipfile"
    PRIORITY = DependencySourcePriority.MANIFEST

    def parse(self, project_path: Path):

        data = self.load(project_path)

        dependencies: dict[str, ScannedDependency] = {}

        self._parse_section(
            data.get("packages", {}),
            dependencies,
        )

        self._parse_section(
            data.get("dev-packages", {}),
            dependencies,
        )

        return list(dependencies.values())

    def _parse_section(
        self,
        packages: dict[str, Any],
        dependencies: dict[str, ScannedDependency],
    ) -> None:

        for name, version in packages.items():
            dependencies.setdefault(
                name.lower(),
                self.dependency(
                    name=name,
                    version=self.normalize_version(version),
                ),
            )
