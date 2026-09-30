from __future__ import annotations

from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_parser import BaseParser


class GoModParser(BaseParser):
    """
    Parser for Go go.mod files.
    """

    FILE = "go.mod"

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
        dependencies: list[ScannedDependency] = []
        in_require_block = False

        file = project_path / self.FILE

        with file.open(
            "r",
            encoding="utf-8",
        ) as stream:
            for raw_line in stream:
                line = raw_line.strip()

                if not line or line.startswith("//"):
                    continue

                if line == "require (":
                    in_require_block = True
                    continue

                if in_require_block and line == ")":
                    in_require_block = False
                    continue

                if line.startswith("require "):
                    dependency = self._parse_dependency(
                        line[len("require ") :],
                    )

                    if dependency is not None:
                        dependencies.append(dependency)

                    continue

                if in_require_block:
                    dependency = self._parse_dependency(line)

                    if dependency is not None:
                        dependencies.append(dependency)

        return dependencies

    def _parse_dependency(
        self,
        line: str,
    ) -> ScannedDependency | None:
        content = line.split(
            "//",
            maxsplit=1,
        )[0].strip()

        parts = content.split()

        if len(parts) < 2:
            return None

        return self.make_dependency(
            name=parts[0],
            version=parts[1],
            ecosystem=Ecosystem.GOLANG,
        )
