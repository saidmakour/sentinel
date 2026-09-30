from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.base import SentinelPlugin
from sentinel.plugins.php.parsers.composer_json_parser import (
    ComposerJsonParser,
)
from sentinel.plugins.php.parsers.composer_lock_parser import (
    ComposerLockParser,
)
from sentinel.plugins.php.scanner import PHPScanner
from sentinel.plugins.php.version_comparator import PHPVersionComparator
from sentinel.scanners.definition import ScannerDefinition
from sentinel.services.version_comparators.base import BaseVersionComparator


class PHPPlugin(SentinelPlugin):
    @property
    def name(self) -> str:
        return "php"

    @property
    def languages(self) -> tuple[str, ...]:
        return ("php",)

    @property
    def scanners(self) -> dict[str, ScannerDefinition]:
        return {
            "php": ScannerDefinition(
                scanner=PHPScanner,
                parsers=(
                    ComposerLockParser(),
                    ComposerJsonParser(),
                ),
                languages=("php",),
            ),
        }

    @property
    def comparators(
        self,
    ) -> dict[Ecosystem, BaseVersionComparator]:
        return {
            Ecosystem.COMPOSER: PHPVersionComparator(),
        }
