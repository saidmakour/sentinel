from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.base import SentinelPlugin
from sentinel.plugins.java.parsers.gradle_kts_parser import GradleKtsParser
from sentinel.plugins.java.parsers.gradle_parser import GradleParser
from sentinel.plugins.java.parsers.pom_parser import PomParser
from sentinel.plugins.java.scanner import JavaScanner
from sentinel.plugins.java.version_comparator import JavaVersionComparator
from sentinel.scanners.definition import ScannerDefinition
from sentinel.services.version_comparators.base import BaseVersionComparator


class JavaPlugin(SentinelPlugin):
    @property
    def name(self) -> str:
        return "java"

    @property
    def languages(self) -> tuple[str, ...]:
        return ("java",)

    @property
    def scanners(self) -> dict[str, ScannerDefinition]:
        return {
            "java": ScannerDefinition(
                scanner=JavaScanner,
                parsers=(
                    PomParser(),
                    GradleParser(),
                    GradleKtsParser(),
                ),
                languages=("java",),
            ),
        }

    @property
    def comparators(
        self,
    ) -> dict[Ecosystem, BaseVersionComparator]:
        return {
            Ecosystem.MAVEN: JavaVersionComparator(),
        }
