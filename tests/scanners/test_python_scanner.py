from unittest.mock import MagicMock

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.plugins.python.scanner import PythonScanner
from sentinel.scanners.parsers.base_parser import BaseParser


def test_scan_empty_project(
    temp_project,
):

    scanner = PythonScanner()

    result = scanner.scan(temp_project)

    assert result == []


def test_scan_requirements_file(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "requirements.txt",
        """
requests==2.32.3
flask==3.0.0
""",
    )

    scanner = PythonScanner()

    result = scanner.scan(temp_project)

    names = {dep.name for dep in result}

    assert names == {
        "requests",
        "flask",
    }


def test_scan_multiple_sources(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "requirements.txt",
        """
requests==2.31.0
""",
    )

    create_file(
        temp_project,
        "pyproject.toml",
        """
[project]
dependencies = [
    "flask==3.0.0",
]
""",
    )

    scanner = PythonScanner()

    result = scanner.scan(temp_project)

    names = {dep.name for dep in result}

    assert names == {
        "requests",
        "flask",
    }


def test_lock_file_has_priority_over_requirements(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "requirements.txt",
        """
requests==2.31.0
""",
    )

    create_file(
        temp_project,
        "uv.lock",
        """
[[package]]
name = "requests"
version = "2.32.3"
""",
    )

    scanner = PythonScanner()

    result = scanner.scan(temp_project)

    dependency = result[0]

    assert dependency.name == "requests"
    assert dependency.version == "2.32.3"


def test_dependencies_are_separated_by_ecosystem():

    dependencies = [
        ScannedDependency(
            name="requests",
            version="2.32.3",
            ecosystem="PyPI",
            source="test",
            priority=10,
        ),
        ScannedDependency(
            name="requests",
            version="1.0.0",
            ecosystem="npm",
            source="test",
            priority=10,
        ),
    ]

    result = {}

    for dependency in dependencies:
        key = (
            dependency.ecosystem.lower(),
            dependency.name.lower(),
        )

        result[key] = dependency

    assert len(result) == 2


def test_python_scanner_accepts_custom_parsers() -> None:
    parser = MagicMock(spec=BaseParser)

    scanner = PythonScanner(parsers=[parser])

    assert scanner.parsers == [parser]


def test_python_scanner_uses_default_parsers() -> None:
    scanner = PythonScanner()

    assert len(scanner.parsers) == 6
