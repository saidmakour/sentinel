from sentinel.plugins.java.parsers.gradle_kts_parser import GradleKtsParser
from sentinel.plugins.java.parsers.gradle_parser import GradleParser
from sentinel.plugins.java.parsers.pom_parser import PomParser
from sentinel.scanners.base import BaseScanner
from sentinel.scanners.parsers.base_parser import BaseParser


class JavaScanner(BaseScanner):
    def __init__(
        self,
        parsers: list[BaseParser] | None = None,
    ) -> None:
        super().__init__(
            parsers
            or [
                PomParser(),
                GradleParser(),
                GradleKtsParser(),
            ]
        )
