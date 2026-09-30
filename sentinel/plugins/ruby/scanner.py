from sentinel.plugins.ruby.parsers.gemfile_lock_parser import GemfileLockParser
from sentinel.plugins.ruby.parsers.gemfile_parser import GemfileParser
from sentinel.scanners.base import BaseScanner
from sentinel.scanners.parsers.base_parser import BaseParser


class RubyScanner(BaseScanner):
    def __init__(
        self,
        parsers: list[BaseParser] | None = None,
    ) -> None:
        super().__init__(
            parsers
            or [
                GemfileLockParser(),
                GemfileParser(),
            ],
        )
