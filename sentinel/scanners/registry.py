from sentinel.scanners.base import BaseScanner


class ScannerRegistry:
    def __init__(
        self,
        scanners: dict[str, type[BaseScanner]] | None = None,
    ) -> None:
        self._scanners = {
            language.lower(): scanner
            for language, scanner in (scanners or {}).items()
        }

    def register(
        self,
        language: str,
        scanner: type[BaseScanner],
    ) -> None:
        self._scanners[language.lower()] = scanner

    def get(
        self,
        language: str,
    ) -> type[BaseScanner] | None:
        return self._scanners.get(language.lower())

    def supports(
        self,
        language: str,
    ) -> bool:
        return language.lower() in self._scanners
