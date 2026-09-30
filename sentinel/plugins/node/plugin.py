from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.base import SentinelPlugin
from sentinel.plugins.node.parsers.package_json_parser import PackageJsonParser
from sentinel.plugins.node.parsers.package_lock_parser import PackageLockParser
from sentinel.plugins.node.parsers.pnpm_lock_parser import PnpmLockParser
from sentinel.plugins.node.parsers.yarn_lock_parser import YarnLockParser
from sentinel.plugins.node.scanner import NodeScanner
from sentinel.plugins.node.version_comparator import NPMVersionComparator
from sentinel.scanners.definition import ScannerDefinition
from sentinel.services.version_comparators.base import BaseVersionComparator


class NodePlugin(SentinelPlugin):
    @property
    def name(self) -> str:
        return "node"

    @property
    def languages(self) -> tuple[str, ...]:
        return (
            "node",
            "javascript",
            "typescript",
        )

    @property
    def scanners(self) -> dict[str, ScannerDefinition]:
        return {
            "node": ScannerDefinition(
                scanner=NodeScanner,
                parsers=(
                    PackageLockParser(),
                    YarnLockParser(),
                    PnpmLockParser(),
                    PackageJsonParser(),
                ),
                languages=(
                    "node",
                    "javascript",
                    "typescript",
                ),
            ),
        }

    @property
    def comparators(
        self,
    ) -> dict[Ecosystem, BaseVersionComparator]:
        return {
            Ecosystem.NPM: NPMVersionComparator(),
        }
