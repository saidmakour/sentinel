from __future__ import annotations

from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.log import get_logger
from sentinel.scanners.parsers.base_parser import BaseParser

logger = get_logger(__name__)


class RequirementsParser(BaseParser):
    """
    Parse Python requirements.txt files.
    """

    FILES = ("requirements.txt",)
    PRIORITY = DependencySourcePriority.MANIFEST

    def supports(self, project_path: Path) -> bool:
        return any(
            (project_path / filename).exists() for filename in self.FILES
        )

    def parse(
        self,
        project_path: Path,
    ) -> list[ScannedDependency]:

        dependencies: dict[str, ScannedDependency] = {}

        for filename in self.FILES:
            file = project_path / filename

            if not file.exists():
                continue

            self._parse_file(file, dependencies)

        return list(dependencies.values())

    def _parse_file(
        self,
        file: Path,
        dependencies: dict[str, ScannedDependency],
    ) -> None:

        logger.debug("Parsing requirements file: %s", file)

        for line in file.read_text(encoding="utf-8").splitlines():
            dependency = self._parse_line(line)

            if dependency:
                dependencies.setdefault(
                    dependency.name.lower(),
                    dependency,
                )

    def _parse_line(
        self,
        line: str,
    ) -> ScannedDependency | None:

        line = line.strip()

        if not line:
            return None

        if line.startswith("#"):
            return None

        if line.startswith("-"):
            return None

        if "==" in line:
            name, version = line.split("==", 1)

        elif ">=" in line:
            name, version = line.split(">=", 1)

        elif "~=" in line:
            name, version = line.split("~=", 1)

        else:
            name = line
            version = "unknown"

        return ScannedDependency(
            name=name.strip(),
            version=version.strip(),
            ecosystem=Ecosystem.PYPI,
            source="requirements.txt",
            priority=self.PRIORITY,
        )
