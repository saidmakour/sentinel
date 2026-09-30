from dataclasses import dataclass

from sentinel.scanners.base import BaseScanner
from sentinel.scanners.parsers.base_parser import BaseParser


@dataclass(frozen=True)
class ScannerDefinition:
    scanner: type[BaseScanner]
    parsers: tuple[BaseParser, ...]
    languages: tuple[str, ...]
