from sentinel.plugins.go.parsers.go_mod_parser import GoModParser
from sentinel.plugins.go.parsers.go_sum_parser import GoSumParser
from sentinel.scanners.base import BaseScanner
from sentinel.scanners.parsers.base_parser import BaseParser


class GoScanner(BaseScanner):
    def __init__(
        self,
        parsers: list[BaseParser] | None = None,
    ) -> None:
        super().__init__(
            parsers
            or [
                GoModParser(),
                GoSumParser(),
            ]
        )
