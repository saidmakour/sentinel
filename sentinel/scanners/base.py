from __future__ import annotations

from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.scanners.parsers.base_parser import BaseParser


class BaseScanner:
    def __init__(
        self,
        parsers: list[BaseParser] | None = None,
    ) -> None:
        self.parsers = parsers or []

    def make_dependency_key(
        self,
        dependency: ScannedDependency,
    ) -> tuple[str, ...]:
        return (
            dependency.ecosystem.lower(),
            dependency.name.lower(),
        )

    def scan(
        self,
        path: Path,
    ) -> list[ScannedDependency]:
        dependencies: dict[
            tuple[str, ...],
            ScannedDependency,
        ] = {}

        for parser in self.parsers:
            if not parser.supports(path):
                continue

            for dependency in parser.parse(path):
                key = self.make_dependency_key(dependency)

                existing = dependencies.get(key)

                if existing is None or dependency.priority < existing.priority:
                    dependencies[key] = dependency

        return sorted(
            dependencies.values(),
            key=lambda dep: (
                dep.ecosystem.lower(),
                dep.name.lower(),
            ),
        )
