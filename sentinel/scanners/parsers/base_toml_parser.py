from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any
from typing import cast

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_parser import BaseParser


class BaseTomlParser(BaseParser):
    FILE: str
    PRIORITY: int

    def supports(
        self,
        project_path: Path,
    ) -> bool:

        return (project_path / self.FILE).exists()

    def load(
        self,
        project_path: Path,
    ) -> dict[str, Any]:

        file = project_path / self.FILE

        with file.open("rb") as f:
            return tomllib.load(f)

    def dependency(
        self,
        *,
        name: str,
        version: str,
        ecosystem: Ecosystem = Ecosystem.PYPI,
    ) -> ScannedDependency:

        return ScannedDependency(
            name=name,
            version=version,
            ecosystem=ecosystem,
            source=self.FILE,
            priority=self.PRIORITY,
        )

    @staticmethod
    def normalize_version(
        version: object,
    ) -> str:

        if isinstance(version, str):
            return version

        if isinstance(version, dict):
            version_dict = cast(dict[str, Any], version)
            value = version_dict.get("version")

            return str(value)

        return "unknown"
