from __future__ import annotations

from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_parser import BaseParser


class YarnLockParser(BaseParser):
    """
    Parser for Yarn v1 yarn.lock files.
    """

    FILE = "yarn.lock"

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

        dependencies: list[ScannedDependency] = []

        current_names: list[str] = []

        for raw_line in file.read_text(
            encoding="utf-8",
        ).splitlines():
            line = raw_line.strip()

            if not line:
                continue

            if line.endswith(":") and not line.startswith("version "):
                current_names = self._parse_names(
                    line,
                )
                continue

            if line.startswith("version "):
                version = self._parse_version(
                    line,
                )

                if version is None:
                    continue

                for name in current_names:
                    dependencies.append(
                        ScannedDependency(
                            name=name,
                            version=version,
                            ecosystem=Ecosystem.NPM,
                            source=self.FILE,
                            priority=self.PRIORITY,
                        )
                    )

                current_names = []

        return dependencies

    @staticmethod
    def _parse_names(
        line: str,
    ) -> list[str]:

        value = line[:-1].strip()

        names: list[str] = []

        for selector in value.split(","):
            selector = selector.strip()

            if selector.startswith('"'):
                selector = selector[1:]

            if selector.endswith('"'):
                selector = selector[:-1]

            if "@" not in selector:
                continue

            name, _ = selector.rsplit(
                "@",
                1,
            )

            if name:
                names.append(name)

        return names

    @staticmethod
    def _parse_version(
        line: str,
    ) -> str | None:

        value = line[len("version ") :].strip()

        if value.startswith('"') and value.endswith('"'):
            return value[1:-1]

        return None
