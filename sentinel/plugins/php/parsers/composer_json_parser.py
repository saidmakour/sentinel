from __future__ import annotations

from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_json_parser import BaseJsonParser


class ComposerJsonParser(BaseJsonParser):
    """
    Parser for composer.json files.
    """

    FILE = "composer.json"

    PRIORITY = DependencySourcePriority.MANIFEST

    def parse(
        self,
        project_path: Path,
    ) -> list[ScannedDependency]:

        data = self.load(project_path)

        dependencies: list[ScannedDependency] = []

        for section in (
            "require",
            "require-dev",
        ):
            packages = self.get_dict(
                data,
                section,
            )

            for name, version in packages.items():
                if not isinstance(version, str):
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
