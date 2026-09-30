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
from sentinel.scanners.base import BaseScanner
from sentinel.scanners.parsers.base_parser import BaseParser


class PythonScanner(BaseScanner):
    def __init__(
        self,
        parsers: list[BaseParser] | None = None,
    ) -> None:
        super().__init__(
            parsers
            or [
                UVLockParser(),
                PoetryLockParser(),
                PipfileLockParser(),
                RequirementsParser(),
                PipfileParser(),
                PyProjectParser(),
            ]
        )
