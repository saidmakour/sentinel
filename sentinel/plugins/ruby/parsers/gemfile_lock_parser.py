from __future__ import annotations

import re
from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_parser import BaseParser


class GemfileLockParser(BaseParser):
    """
    Parser for Gemfile.lock files.
    """

    FILE = "Gemfile.lock"
    PRIORITY = DependencySourcePriority.LOCK_FILE

    _SPECS_PATTERN = re.compile(r"^\s{2}specs:\s*$")

    _GEM_PATTERN = re.compile(
        r"^ {4}"
        r"(?P<name>[^\s(]+)"
        r"\s+\("
        r"(?P<version>[^)]+)"
        r"\)$",
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
        in_specs = False

        with file.open("r", encoding="utf-8") as f:
            for line in f:
                if self._is_specs_section(line):
                    in_specs = True
                    continue

                if in_specs and self._is_section_start(line):
                    in_specs = False
                    continue

                if not in_specs:
                    continue

                dependency = self._parse_spec(line)

                if dependency is not None:
                    dependencies.append(dependency)

        return dependencies

    @classmethod
    def _is_specs_section(
        cls,
        line: str,
    ) -> bool:
        return cls._SPECS_PATTERN.match(line) is not None

    @staticmethod
    def _is_section_start(
        line: str,
    ) -> bool:
        return (
            bool(line.strip())
            and not line.startswith(" ")
            and not line.startswith("\t")
        )

    @classmethod
    def _parse_spec(
        cls,
        line: str,
    ) -> ScannedDependency | None:
        match = cls._GEM_PATTERN.match(line)

        if match is None:
            return None

        return ScannedDependency(
            name=match.group("name"),
            version=match.group("version"),
            ecosystem=Ecosystem.RUBYGEMS,
            source=cls.FILE,
            priority=cls.PRIORITY,
        )
