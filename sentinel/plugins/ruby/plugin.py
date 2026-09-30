from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.base import SentinelPlugin
from sentinel.plugins.ruby.parsers.gemfile_lock_parser import GemfileLockParser
from sentinel.plugins.ruby.parsers.gemfile_parser import GemfileParser
from sentinel.plugins.ruby.scanner import RubyScanner
from sentinel.plugins.ruby.version_comparator import RubyVersionComparator
from sentinel.scanners.definition import ScannerDefinition
from sentinel.services.version_comparators.base import BaseVersionComparator


class RubyPlugin(SentinelPlugin):
    @property
    def name(self) -> str:
        return "ruby"

    @property
    def languages(self) -> tuple[str, ...]:
        return ("ruby",)

    @property
    def scanners(self) -> dict[str, ScannerDefinition]:
        return {
            "ruby": ScannerDefinition(
                scanner=RubyScanner,
                parsers=(
                    GemfileLockParser(),
                    GemfileParser(),
                ),
                languages=("ruby",),
            ),
        }

    @property
    def comparators(
        self,
    ) -> dict[Ecosystem, BaseVersionComparator]:
        return {
            Ecosystem.RUBYGEMS: RubyVersionComparator(),
        }
