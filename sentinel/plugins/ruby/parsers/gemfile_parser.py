from __future__ import annotations

import re
from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_parser import BaseParser


class GemfileParser(BaseParser):
    """
    Parser for Gemfile files.
    """

    FILE = "Gemfile"

    PRIORITY = DependencySourcePriority.MANIFEST

    _GEM_CALL_PATTERN = re.compile(
        r"""
        ^\s*
        gem
        \s*
        \(?
        \s*
        ["']
        (?P<name>[^"']+)
        ["']
        (?P<rest>.*)
        """,
        re.VERBOSE,
    )

    _VERSION_PATTERN = re.compile(
        r"""
        ["']
        (?P<version>[^"']+)
        ["']
        """,
        re.VERBOSE,
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

        with file.open(
            "r",
            encoding="utf-8",
        ) as f:
            for line in f:
                dependency = self._parse_line(line)

                if dependency is not None:
                    dependencies.append(dependency)

        return dependencies

    def _parse_line(
        self,
        line: str,
    ) -> ScannedDependency | None:
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            return None

        match = self._GEM_CALL_PATTERN.match(line)

        if match is None:
            return None

        name = match.group("name").strip()

        if not name:
            return None

        version = self._extract_version(
            match.group("rest"),
        )

        return ScannedDependency(
            name=name,
            version=version,
            ecosystem=Ecosystem.RUBYGEMS,
            source=self.FILE,
            priority=self.PRIORITY,
        )

    @classmethod
    def _extract_version(
        cls,
        value: str,
    ) -> str:
        match = cls._VERSION_PATTERN.search(value)

        if match is None:
            return "*"

        return match.group("version")
