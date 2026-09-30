from __future__ import annotations

from pathlib import Path
from typing import Any
from typing import cast

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_json_parser import BaseJsonParser


class ComposerLockParser(BaseJsonParser):
    """
    Parser for composer.lock files.
    """

    FILE = "composer.lock"

    PRIORITY = DependencySourcePriority.LOCK_FILE

    def parse(
        self,
        project_path: Path,
    ) -> list[ScannedDependency]:

        data = self.load(project_path)

        packages = self.get_list(
            data,
            "packages",
        )

        dependencies: list[ScannedDependency] = []

        for package in packages:
            if not isinstance(package, dict):
                continue

            package = cast(dict[str, Any], package)
            name = package.get("name")
            version = package.get("version")

            if not isinstance(name, str) or not isinstance(version, str):
                continue

            dependencies.append(
                ScannedDependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.COMPOSER,
                    source=self.FILE,
                    priority=self.PRIORITY,
                )
            )

        return dependencies
