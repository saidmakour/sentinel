from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_parser import BaseParser


class GoSumParser(BaseParser):
    """
    Parser for Go go.sum files.
    """

    FILE = "go.sum"
    PRIORITY = DependencySourcePriority.LOCK_FILE

    def supports(self, project_path: Path) -> bool:
        return (project_path / self.FILE).exists()

    def parse(self, project_path: Path) -> list[ScannedDependency]:
        dependencies: list[ScannedDependency] = []
        seen: set[tuple[str, str]] = set()

        file = project_path / self.FILE

        with file.open("r", encoding="utf-8") as stream:
            for raw_line in stream:
                dependency = self._parse_dependency(raw_line)

                if dependency is None:
                    continue

                key = (
                    dependency.name,
                    dependency.version,
                )

                if key in seen:
                    continue

                seen.add(key)
                dependencies.append(dependency)

        return dependencies

    def _parse_dependency(
        self,
        line: str,
    ) -> ScannedDependency | None:
        parts = line.strip().split()

        if len(parts) < 2:
            return None

        name = parts[0]
        version = parts[1]

        if version.endswith("/go.mod"):
            version = version.removesuffix("/go.mod")

        return self.make_dependency(
            name=name,
            version=version,
            ecosystem=Ecosystem.GOLANG,
        )
