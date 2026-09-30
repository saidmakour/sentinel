from __future__ import annotations

from pathlib import Path
from typing import Any
from typing import cast

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_toml_parser import BaseTomlParser


class GradleVersionCatalogParser(BaseTomlParser):
    """
    Parser for Gradle Version Catalog files.
    """

    FILE = "gradle/libs.versions.toml"

    PRIORITY = DependencySourcePriority.MANIFEST

    def parse(
        self,
        project_path: Path,
    ) -> list[ScannedDependency]:

        data = self.load(project_path)
        versions_data = data.get(
            "versions",
            {},
        )

        libraries_data = data.get(
            "libraries",
            {},
        )

        if not isinstance(versions_data, dict):
            versions: dict[str, Any] = {}
        else:
            versions = cast(
                dict[str, Any],
                versions_data,
            )

        if not isinstance(libraries_data, dict):
            return []

        libraries = cast(
            dict[str, Any],
            libraries_data,
        )

        dependencies: list[ScannedDependency] = []

        for library in libraries.values():
            if not isinstance(library, dict):
                continue

            library_data = cast(
                dict[str, Any],
                library,
            )

            dependency = self._parse_library(
                library_data,
                versions,
            )

            if dependency is not None:
                dependencies.append(
                    dependency,
                )

        return dependencies

    def resolve(
        self,
        alias: str,
        project_path: Path,
    ) -> ScannedDependency | None:
        """
        Resolve a Gradle Version Catalog alias.

        Returns None when the Version Catalog does not exist
        or when the alias cannot be resolved.
        """

        if not self.supports(project_path):
            return None

        data = self.load(project_path)

        versions = cast(
            dict[str, Any],
            data.get(
                "versions",
                {},
            ),
        )

        libraries = cast(
            dict[str, dict[str, Any]],
            data.get(
                "libraries",
                {},
            ),
        )

        library_name = self._normalize_alias(alias)

        library = libraries.get(library_name)

        if not isinstance(library, dict):
            return None

        return self._parse_library(
            library,
            versions,
        )

    @staticmethod
    def _normalize_alias(
        alias: str,
    ) -> str:

        normalized = alias.strip()

        if normalized.startswith("libs."):
            normalized = normalized[5:]

        return normalized.replace(".", "-")

    def _parse_library(
        self,
        library: dict[str, Any],
        versions: dict[str, Any],
    ) -> ScannedDependency | None:

        name = self._get_dependency_name(library)

        if name is None:
            return None

        version = self._get_dependency_version(
            library,
            versions,
        )

        if version is None:
            return None

        return self.dependency(
            name=name,
            version=version,
            ecosystem=Ecosystem.MAVEN,
        )

    @staticmethod
    def _get_dependency_name(
        library: dict[str, Any],
    ) -> str | None:

        module = library.get("module")

        if isinstance(module, str) and module:
            return module

        group = library.get("group")
        name = library.get("name")

        if isinstance(group, str) and isinstance(name, str) and group and name:
            return f"{group}:{name}"

        return None

    @staticmethod
    def _get_dependency_version(
        library: dict[str, Any],
        versions: dict[str, Any],
    ) -> str | None:

        version = library.get("version")

        if isinstance(version, str) and version:
            return version

        if not isinstance(version, dict):
            return None

        version_data = cast(
            dict[str, Any],
            version,
        )

        version_ref = version_data.get("ref")

        if isinstance(version_ref, str) and version_ref:
            resolved_version = versions.get(version_ref)

            if isinstance(resolved_version, str) and resolved_version:
                return resolved_version

        for key in (
            "strictly",
            "require",
            "prefer",
        ):
            value = version_data.get(key)

            if isinstance(value, str) and value:
                return value

        return None
