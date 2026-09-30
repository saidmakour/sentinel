from unittest.mock import MagicMock

from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.python.parsers.pipfile_parser import PipfileParser


def test_parse_packages(
    tmp_path,
):
    parser = PipfileParser()

    parser.load = MagicMock(
        return_value={
            "packages": {
                "requests": "--2.31.0",
                "httpx": "--0.27.0",
            },
        }
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 2

    requests = next(
        dependency
        for dependency in dependencies
        if dependency.name == "requests"
    )

    assert requests.version == "--2.31.0"
    assert requests.ecosystem == Ecosystem.PYPI.value
    assert requests.source == "Pipfile"
    assert requests.priority == parser.PRIORITY


def test_parse_dev_packages(
    tmp_path,
):
    parser = PipfileParser()

    parser.load = MagicMock(
        return_value={
            "dev-packages": {
                "pytest": "--8.2.0",
            },
        }
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    assert dependencies[0].name == "pytest"
    assert dependencies[0].version == "--8.2.0"
    assert dependencies[0].ecosystem == "PyPI"
    assert dependencies[0].source == "Pipfile"


def test_parse_packages_and_dev_packages(
    tmp_path,
):
    parser = PipfileParser()

    parser.load = MagicMock(
        return_value={
            "packages": {
                "requests": "==2.31.0",
            },
            "dev-packages": {
                "pytest": "==8.2.0",
            },
        }
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 2

    dependency_names = {dependency.name for dependency in dependencies}

    assert dependency_names == {
        "requests",
        "pytest",
    }


def test_parse_deduplicates_dependencies_case_insensitively(
    tmp_path,
):
    parser = PipfileParser()

    parser.load = MagicMock(
        return_value={
            "packages": {
                "Requests": "--2.31.0",
            },
            "dev-packages": {
                "requests": "--2.32.0",
            },
        }
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    assert dependencies[0].name == "Requests"
    assert dependencies[0].version == "--2.31.0"


def test_parse_empty_pipfile(
    tmp_path,
):
    parser = PipfileParser()

    parser.load = MagicMock(return_value={})

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_missing_sections(
    tmp_path,
):
    parser = PipfileParser()

    parser.load = MagicMock(
        return_value={
            "source": [
                {
                    "name": "pypi",
                    "url": "https://pypi.org/simple",
                },
            ],
        }
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []
