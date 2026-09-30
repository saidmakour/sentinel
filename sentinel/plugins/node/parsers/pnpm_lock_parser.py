from __future__ import annotations

from pathlib import Path
from typing import Any
from typing import cast

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_yaml_parser import BaseYamlParser


class PnpmLockParser(BaseYamlParser):
    """
    Parser for pnpm-lock.yaml files.
    """

    FILE = "pnpm-lock.yaml"

    PRIORITY = DependencySourcePriority.LOCK_FILE

    def parse(
        self,
        project_path: Path,
    ) -> list[ScannedDependency]:

        data = self.load(project_path)

        dependencies: list[ScannedDependency] = []

        snapshots = data.get(
            "snapshots",
            {},
        )

        if not isinstance(snapshots, dict):
            return dependencies

        snapshots_data = cast(
            dict[str, Any],
            snapshots,
        )

        for package_key in snapshots_data:
            name, version = self._parse_package_key(
                package_key,
            )

            if name is None or version is None:
                continue

            dependencies.append(
                ScannedDependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    source=self.FILE,
                    priority=self.PRIORITY,
                )
            )

        return dependencies

    @staticmethod
    def _parse_package_key(
        package_key: object,
    ) -> tuple[str | None, str | None]:

        if not isinstance(package_key, str):
            return None, None

        value = package_key

        if value.startswith("/"):
            value = value[1:]

        if "@" not in value:
            return None, None

        name, version = value.rsplit(
            "@",
            1,
        )

        if not name or not version:
            return None, None

        return name, version
