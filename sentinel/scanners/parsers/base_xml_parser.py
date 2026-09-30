from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from sentinel.exceptions.scanner import InvalidFileError
from sentinel.scanners.parsers.base_parser import BaseParser


class BaseXmlParser(BaseParser):
    """
    Base class for XML parsers.
    """

    def supports(
        self,
        project_path: Path,
    ) -> bool:

        return (project_path / self.FILE).exists()

    def load(
        self,
        project_path: Path,
    ) -> ET.Element:

        file = project_path / self.FILE

        try:
            tree = ET.parse(file)
            root = tree.getroot()
            self._strip_namespaces(root)
            return tree.getroot()

        except ET.ParseError as exc:
            raise InvalidFileError(f"Invalid XML in '{self.FILE}'") from exc

    def find_text(
        self,
        root: ET.Element,
        path: str,
    ) -> str | None:

        element = root.find(path)

        if element is None:
            return None

        if element.text is None:
            return None

        value = element.text.strip()

        return value or None

    def find_all(
        self,
        root: ET.Element,
        path: str,
    ) -> list[ET.Element]:

        return list(root.findall(path))

    @staticmethod
    def _strip_namespaces(
        root: ET.Element,
    ) -> None:
        """
        Remove XML namespaces in-place.

        This allows parsers to use simple XPath expressions
        regardless of whether the document declares namespaces.
        """
        for element in root.iter():
            if "}" in element.tag:
                element.tag = element.tag.split("}", 1)[1]
