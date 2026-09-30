from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.base import SentinelPlugin
from sentinel.plugins.go.parsers.go_mod_parser import GoModParser
from sentinel.plugins.go.parsers.go_sum_parser import GoSumParser
from sentinel.plugins.go.scanner import GoScanner
from sentinel.plugins.go.version_comparator import GoVersionComparator
from sentinel.scanners.definition import ScannerDefinition
from sentinel.services.version_comparators.base import BaseVersionComparator


class GoPlugin(SentinelPlugin):
    @property
    def name(self) -> str:
        return "go"

    @property
    def languages(self) -> tuple[str, ...]:
        return ("go",)

    @property
    def scanners(self) -> dict[str, ScannerDefinition]:
        return {
            "go": ScannerDefinition(
                scanner=GoScanner,
                parsers=(
                    GoModParser(),
                    GoSumParser(),
                ),
                languages=("go",),
            ),
        }

    @property
    def comparators(
        self,
    ) -> dict[Ecosystem, BaseVersionComparator]:
        return {
            Ecosystem.GOLANG: GoVersionComparator(),
        }
