from __future__ import annotations

import re
from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.java.parsers.gradle_version_catalog_parser import (
    GradleVersionCatalogParser,
)
from sentinel.scanners.parsers.base_parser import BaseParser


class GradleKtsParser(BaseParser):
    """
    Parser for Gradle Kotlin DSL build.gradle.kts files.
    """

    FILE = "build.gradle.kts"

    PRIORITY = DependencySourcePriority.MANIFEST

    CONFIGURATIONS = (
        "implementation",
        "api",
        "compileOnly",
        "runtimeOnly",
        "testImplementation",
        "testCompileOnly",
        "testRuntimeOnly",
        "annotationProcessor",
    )

    DEPENDENCY_PATTERN = re.compile(
        rf"""
        (?P<configuration>{"|".join(CONFIGURATIONS)})
        \s*\(\s*
        ["']
        (?P<group>[^:"']+)
        :
        (?P<artifact>[^:"']+)
        :
        (?P<version>[^"']+)
        ["']
        \s*\)
        """,
        re.VERBOSE,
    )

    VERSION_CATALOG_PATTERN = re.compile(
        rf"""
        (?P<configuration>{"|".join(CONFIGURATIONS)})
        \s*\(\s*
        (?P<alias>libs(?:\.[A-Za-z0-9_-]+)+)
        \s*\)
        """,
        re.VERBOSE,
    )

    def __init__(
        self,
        version_catalog_parser: GradleVersionCatalogParser | None = None,
    ) -> None:

        self.version_catalog_parser = (
            version_catalog_parser or GradleVersionCatalogParser()
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

        if not file.exists():
            return []

        content = file.read_text(encoding="utf-8")

        dependencies = self._parse_standard_dependencies(
            content,
        )

        dependencies.extend(
            self._parse_version_catalog_dependencies(
                content,
                project_path,
            )
        )

        return dependencies

    def _parse_standard_dependencies(
        self,
        content: str,
    ) -> list[ScannedDependency]:

        dependencies: list[ScannedDependency] = []

        for match in self.DEPENDENCY_PATTERN.finditer(content):
            group = match.group("group")
            artifact = match.group("artifact")
            version = match.group("version")

            dependencies.append(
                ScannedDependency(
                    name=f"{group}:{artifact}",
                    version=version,
                    ecosystem=Ecosystem.MAVEN,
                    source=self.FILE,
                    priority=self.PRIORITY,
                )
            )

        return dependencies

    def _parse_version_catalog_dependencies(
        self,
        content: str,
        project_path: Path,
    ) -> list[ScannedDependency]:

        dependencies: list[ScannedDependency] = []

        for match in self.VERSION_CATALOG_PATTERN.finditer(content):
            alias = match.group("alias")

            dependency = self.version_catalog_parser.resolve(
                alias,
                project_path,
            )

            if dependency is not None:
                dependency.source = self.FILE
                dependency.priority = self.PRIORITY

                dependencies.append(dependency)

        return dependencies
