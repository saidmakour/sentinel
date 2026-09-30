import json
from pathlib import Path

import pytest

from sentinel.exceptions.scanner import InvalidManifestError
from sentinel.scanners.parsers.base_json_parser import BaseJsonParser


class ConcreteJsonParser(BaseJsonParser):
    FILE = "test.json"
    PRIORITY = 100

    def parse(
        self,
        project_path: Path,
    ):
        return []


def test_supports_returns_true_when_file_exists(
    tmp_path,
):
    file = tmp_path / "test.json"
    file.write_text(
        "{}",
        encoding="utf-8",
    )

    parser = ConcreteJsonParser()

    assert parser.supports(tmp_path) is True


def test_supports_returns_false_when_file_does_not_exist(
    tmp_path,
):
    parser = ConcreteJsonParser()

    assert parser.supports(tmp_path) is False


def test_load_returns_json_data(
    tmp_path,
):
    data = {
        "name": "sentinel",
        "dependencies": {
            "requests": "^2.31.0",
        },
    }

    file = tmp_path / "test.json"
    file.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    parser = ConcreteJsonParser()

    result = parser.load(tmp_path)

    assert result == data


def test_load_raises_invalid_manifest_error_for_invalid_json(
    tmp_path,
):
    file = tmp_path / "test.json"
    file.write_text(
        "{ invalid json",
        encoding="utf-8",
    )

    parser = ConcreteJsonParser()

    with pytest.raises(
        InvalidManifestError,
        match="Invalid JSON in test.json",
    ):
        parser.load(tmp_path)


def test_get_dict_returns_dictionary():
    parser = ConcreteJsonParser()

    data = {
        "dependencies": {
            "requests": "^2.31.0",
        },
    }

    result = parser.get_dict(
        data,
        "dependencies",
    )

    assert result == {
        "requests": "^2.31.0",
    }


def test_get_dict_returns_empty_dict_for_invalid_value():
    parser = ConcreteJsonParser()

    data = {
        "dependencies": [
            "requests",
        ],
    }

    result = parser.get_dict(
        data,
        "dependencies",
    )

    assert result == {}


def test_get_list_returns_list():
    parser = ConcreteJsonParser()

    data = {
        "dependencies": [
            "requests",
            "httpx",
        ],
    }

    result = parser.get_list(
        data,
        "dependencies",
    )

    assert result == [
        "requests",
        "httpx",
    ]


def test_get_list_returns_empty_list_for_invalid_value():
    parser = ConcreteJsonParser()

    data = {
        "dependencies": {
            "requests": "^2.31.0",
        },
    }

    result = parser.get_list(
        data,
        "dependencies",
    )

    assert result == []


def test_get_str_returns_string():
    parser = ConcreteJsonParser()

    data = {
        "name": "sentinel",
    }

    result = parser.get_str(
        data,
        "name",
    )

    assert result == "sentinel"


def test_get_str_returns_empty_string_for_invalid_value():
    parser = ConcreteJsonParser()

    data = {
        "name": 123,
    }

    result = parser.get_str(
        data,
        "name",
    )

    assert result == ""
