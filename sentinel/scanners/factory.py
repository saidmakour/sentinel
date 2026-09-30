from sentinel.exceptions.scanner import UnsupportedLanguageError
from sentinel.plugins.registry import PluginRegistry
from sentinel.scanners.base import BaseScanner


class ScannerFactory:
    def __init__(
        self,
        registry: PluginRegistry,
    ) -> None:
        self.registry = registry

    def create(
        self,
        language: str,
    ) -> BaseScanner:
        definition = self.registry.scanners.get(
            language.lower(),
        )

        if definition is None:
            raise UnsupportedLanguageError(f"Unsupported language: {language}")

        return definition.scanner(
            parsers=list(definition.parsers),
        )
