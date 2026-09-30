from __future__ import annotations

from pathlib import Path
from typing import Any

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_json_parser import BaseJsonParser


class PackageLockParser(BaseJsonParser):
    """
    Parser for npm package-lock.json files.
    """

    FILE = "package-lock.json"
    PRIORITY = DependencySourcePriority.LOCK_FILE

    def parse(
        self,
        project_path: Path,
    ) -> list[ScannedDependency]:

        data = self.load(project_path)

        dependencies: list[ScannedDependency] = []

        packages: dict[str, Any] = data.get(
            "packages",
            {},
        )

        for package_path, package_data in packages.items():
            if not package_path.startswith("node_modules/"):
                continue

            name = package_path.replace(
                "node_modules/",
                "",
            )

            version = package_data.get(
                "version",
            )

            if not version:
                continue

            dependencies.append(
                ScannedDependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    priority=self.PRIORITY,
                    source=self.FILE,
                )
            )

        return dependencies
