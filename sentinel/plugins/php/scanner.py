from sentinel.plugins.php.parsers.composer_json_parser import (
    ComposerJsonParser,
)
from sentinel.plugins.php.parsers.composer_lock_parser import (
    ComposerLockParser,
)
from sentinel.scanners.base import BaseScanner
from sentinel.scanners.parsers.base_parser import BaseParser


class PHPScanner(BaseScanner):
    def __init__(
        self,
        parsers: list[BaseParser] | None = None,
    ) -> None:
        super().__init__(
            parsers
            or [
                ComposerLockParser(),
                ComposerJsonParser(),
            ]
        )
