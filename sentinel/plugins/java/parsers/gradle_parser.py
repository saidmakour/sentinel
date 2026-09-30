from __future__ import annotations

from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_parser import BaseParser


class GradleParser(BaseParser):
    """
    Parser for Gradle build.gradle files.
    """

    FILE = "build.gradle"

    PRIORITY = DependencySourcePriority.MANIFEST

    PREFIXES = (
        "implementation",
        "api",
        "compileOnly",
        "runtimeOnly",
        "testImplementation",
        "testRuntimeOnly",
    )

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

        dependencies: list[ScannedDependency] = []

        for line in file.read_text(
            encoding="utf-8",
        ).splitlines():
            dependency = self._parse_dependency(
                line.strip(),
            )

            if dependency is not None:
                dependencies.append(
                    dependency,
                )

        return dependencies

    def _parse_dependency(
        self,
        line: str,
    ) -> ScannedDependency | None:

        if not line.startswith(self.PREFIXES):
            return None

        quote = "'" if "'" in line else '"'

        try:
            start = line.index(quote)
            end = line.rindex(quote)
        except ValueError:
            return None

        coordinates = line[start + 1 : end]

        parts = coordinates.split(":")

        if len(parts) != 3:
            return None

        group_id, artifact_id, version = parts

        return ScannedDependency(
            name=f"{group_id}:{artifact_id}",
            version=version,
            ecosystem=Ecosystem.MAVEN,
            source=self.FILE,
            priority=self.PRIORITY,
        )
