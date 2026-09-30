from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from typing import cast

from sentinel.exceptions.scanner import InvalidManifestError
from sentinel.scanners.parsers.base_parser import BaseParser
from sentinel.scanners.parsers.types import JsonArray
from sentinel.scanners.parsers.types import JsonObject


class BaseJsonParser(BaseParser):
    """
    Base class for JSON dependency parsers.
    """

    def supports(
        self,
        project_path: Path,
    ) -> bool:
        return (project_path / self.FILE).exists()

    def load(
        self,
        project_path: Path,
    ) -> JsonObject:
        file = project_path / self.FILE
        try:
            with file.open(
                "r",
                encoding="utf-8",
            ) as f:
                data: dict[str, Any] = json.load(f)

        except json.JSONDecodeError as exc:
            raise InvalidManifestError(f"Invalid JSON in {self.FILE}") from exc

        return data

    def get_dict(
        self,
        data: JsonObject,
        key: str,
    ) -> JsonObject:
        """Récupérer un dictionnaire"""
        value = data.get(key)

        if isinstance(value, dict):
            return cast(JsonObject, value)

        return {}

    def get_list(
        self,
        data: JsonObject,
        key: str,
    ) -> JsonArray:
        """Récupérer une liste"""
        value = data.get(key)

        if isinstance(value, list):
            return cast(JsonArray, value)

        return []

    def get_str(
        self,
        data: dict[str, Any],
        key: str,
    ) -> str:
        """Récupérer une chaine"""
        value = data.get(key)

        if isinstance(value, str):
            return value

        return ""

    def get_required_str(
        self,
        data: dict[str, Any],
        key: str,
    ) -> str | None: ...
