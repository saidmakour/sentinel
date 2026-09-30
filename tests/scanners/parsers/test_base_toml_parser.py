from pathlib import Path

from sentinel.scanners.parsers.base_toml_parser import BaseTomlParser


class ConcreteTomlParser(BaseTomlParser):
    FILE = "test.toml"
    PRIORITY = 100

    def parse(
        self,
        project_path: Path,
    ):
        return []


def test_supports_returns_true_when_file_exists(
    tmp_path,
):
    file = tmp_path / "test.toml"
    file.write_text(
        'name = "sentinel"\n',
        encoding="utf-8",
    )

    parser = ConcreteTomlParser()

    assert parser.supports(tmp_path) is True


def test_supports_returns_false_when_file_does_not_exist(
    tmp_path,
):
    parser = ConcreteTomlParser()

    assert parser.supports(tmp_path) is False


def test_load_returns_toml_data(
    tmp_path,
):
    file = tmp_path / "test.toml"
    file.write_text(
        """
        name = "sentinel"
        version = "1.0.0"

        [dependencies]
        requests = "==2.31.0"
        """,
        encoding="utf-8",
    )

    parser = ConcreteTomlParser()

    result = parser.load(tmp_path)

    assert result == {
        "name": "sentinel",
        "version": "1.0.0",
        "dependencies": {
            "requests": "==2.31.0",
        },
    }


def test_dependency_creates_scanned_dependency(
    tmp_path,
):
    parser = ConcreteTomlParser()

    dependency = parser.dependency(
        name="requests",
        version="==2.31.0",
    )

    assert dependency.name == "requests"
    assert dependency.version == "==2.31.0"
    assert dependency.ecosystem == "PyPI"
    assert dependency.source == "test.toml"
    assert dependency.priority == 100


def test_normalize_version_returns_string():
    result = ConcreteTomlParser.normalize_version(
        "==2.31.0",
    )

    assert result == "==2.31.0"


def test_normalize_version_returns_version_from_dict():
    result = ConcreteTomlParser.normalize_version(
        {
            "version": "2.31.0",
        },
    )

    assert result == "2.31.0"


def test_normalize_version_returns_string_for_dict_value():
    result = ConcreteTomlParser.normalize_version(
        {
            "version": 2,
        },
    )

    assert result == "2"


def test_normalize_version_returns_unknown_for_missing_version():
    result = ConcreteTomlParser.normalize_version(
        {
            "extras": [
                "security",
            ],
        },
    )

    assert result == "None"


def test_normalize_version_returns_unknown_for_unsupported_type():
    result = ConcreteTomlParser.normalize_version(
        None,
    )

    assert result == "unknown"
