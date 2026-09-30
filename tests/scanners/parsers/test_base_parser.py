from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_parser import BaseParser


class ConcreteParser(BaseParser):
    FILE = "requirements.txt"
    PRIORITY = 100

    def supports(
        self,
        project_path: Path,
    ) -> bool:
        return True

    def parse(
        self,
        project_path: Path,
    ) -> list[ScannedDependency]:
        return []


def test_make_dependency_creates_scanned_dependency():
    parser = ConcreteParser()

    dependency = parser.make_dependency(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
    )

    assert dependency.name == "requests"
    assert dependency.version == "2.31.0"
    assert dependency.ecosystem == Ecosystem.PYPI.value
    assert dependency.source == "requirements.txt"
    assert dependency.priority == 100
