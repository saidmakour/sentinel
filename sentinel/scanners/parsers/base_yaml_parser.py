from __future__ import annotations

from pathlib import Path
from typing import Any
from typing import cast

import yaml

from sentinel.scanners.parsers.base_parser import BaseParser


class BaseYamlParser(BaseParser):
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

        with file.open(
            "r",
            encoding="utf-8",
        ) as stream:
            data = yaml.safe_load(stream)

        if not isinstance(data, dict):
            return {}

        return cast(
            dict[str, Any],
            data,
        )
