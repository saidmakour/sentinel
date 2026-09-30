from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_parser import BaseParser


class PipfileLockParser(BaseParser):
    """
    Parse Pipfile.lock dependencies.
    """

    FILE = "Pipfile.lock"
    PRIORITY = DependencySourcePriority.LOCK_FILE

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

        data = json.loads(file.read_text(encoding="utf-8"))

        dependencies: dict[str, ScannedDependency] = {}

        self._parse_section(
            data.get("default", {}),
            dependencies,
        )

        self._parse_section(
            data.get("develop", {}),
            dependencies,
        )

        return list(dependencies.values())

    def _parse_section(
        self,
        packages: dict[str, Any],
        dependencies: dict[str, ScannedDependency],
    ) -> None:

        for name, metadata in packages.items():
            version = metadata.get(
                "version",
                "unknown",
            )

            if version.startswith("=="):
                version = version[2:]

            dependencies.setdefault(
                name.lower(),
                ScannedDependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.PYPI,
                    source=self.FILE,
                    priority=self.PRIORITY,
                ),
            )
