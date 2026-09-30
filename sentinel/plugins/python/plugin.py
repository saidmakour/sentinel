from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.base import SentinelPlugin
from sentinel.plugins.python.parsers.pipfile_lock_parser import (
    PipfileLockParser,
)
from sentinel.plugins.python.parsers.pipfile_parser import PipfileParser
from sentinel.plugins.python.parsers.poetry_lock_parser import PoetryLockParser
from sentinel.plugins.python.parsers.pyproject_parser import PyProjectParser
from sentinel.plugins.python.parsers.requirements_parser import (
    RequirementsParser,
)
from sentinel.plugins.python.parsers.uv_lock_parser import UVLockParser
from sentinel.plugins.python.scanner import PythonScanner
from sentinel.plugins.python.version_comparator import PyPIVersionComparator
from sentinel.scanners.definition import ScannerDefinition
from sentinel.services.version_comparators.base import BaseVersionComparator


class PythonPlugin(SentinelPlugin):
    @property
    def name(self) -> str:
        return "python"

    @property
    def languages(self) -> tuple[str, ...]:
        return ("python",)

    @property
    def scanners(self) -> dict[str, ScannerDefinition]:
        return {
            "python": ScannerDefinition(
                scanner=PythonScanner,
                parsers=(
                    UVLockParser(),
                    PoetryLockParser(),
                    PipfileLockParser(),
                    RequirementsParser(),
                    PipfileParser(),
                    PyProjectParser(),
                ),
                languages=("python",),
            ),
        }

    @property
    def comparators(
        self,
    ) -> dict[Ecosystem, BaseVersionComparator]:
        return {
            Ecosystem.PYPI: PyPIVersionComparator(),
        }
