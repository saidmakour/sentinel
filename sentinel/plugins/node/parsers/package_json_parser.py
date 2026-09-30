from __future__ import annotations

from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_json_parser import BaseJsonParser


class PackageJsonParser(BaseJsonParser):
    """
    Parser for package.json.
    """

    FILE = "package.json"

    PRIORITY = DependencySourcePriority.MANIFEST

    def parse(
        self,
        project_path: Path,
    ) -> list[ScannedDependency]:

        data = self.load(project_path)

        dependencies: list[ScannedDependency] = []

        for section in (
            "dependencies",
            "devDependencies",
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
                        ecosystem=Ecosystem.NPM,
                        source=self.FILE,
                        priority=self.PRIORITY,
                    )
                )

        return dependencies
