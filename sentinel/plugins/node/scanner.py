from sentinel.plugins.node.parsers.package_json_parser import PackageJsonParser
from sentinel.plugins.node.parsers.package_lock_parser import PackageLockParser
from sentinel.plugins.node.parsers.pnpm_lock_parser import PnpmLockParser
from sentinel.plugins.node.parsers.yarn_lock_parser import YarnLockParser
from sentinel.scanners.base import BaseScanner
from sentinel.scanners.parsers.base_parser import BaseParser


class NodeScanner(BaseScanner):
    def __init__(
        self,
        parsers: list[BaseParser] | None = None,
    ) -> None:
        super().__init__(
            parsers
            or [
                PackageLockParser(),
                YarnLockParser(),
                PnpmLockParser(),
                PackageJsonParser(),
            ]
        )
