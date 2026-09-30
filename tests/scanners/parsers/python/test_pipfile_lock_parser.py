import json

from sentinel.plugins.python.parsers.pipfile_lock_parser import (
    PipfileLockParser,
)


def test_supports_returns_true_when_pipfile_lock_exists(
    tmp_path,
):
    pipfile_lock = tmp_path / "Pipfile.lock"
    pipfile_lock.write_text(
        "{}",
        encoding="utf-8",
    )

    parser = PipfileLockParser()

    assert parser.supports(tmp_path) is True


def test_supports_returns_false_when_pipfile_lock_does_not_exist(
    tmp_path,
):
    parser = PipfileLockParser()

    assert parser.supports(tmp_path) is False


def test_parse_default_dependencies(
    tmp_path,
):
    data = {
        "default": {
            "requests": {
                "version": "==2.31.0",
            },
            "httpx": {
                "version": "0.27.0",
            },
        },
    }

    pipfile_lock = tmp_path / "Pipfile.lock"
    pipfile_lock.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    parser = PipfileLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 2

    requests = next(
        dependency
        for dependency in dependencies
        if dependency.name == "requests"
    )

    assert requests.version == "2.31.0"
    assert requests.ecosystem == "PyPI"
    assert requests.source == "Pipfile.lock"
    assert requests.priority == parser.PRIORITY


def test_parse_develop_dependencies(
    tmp_path,
):
    data = {
        "develop": {
            "pytest": {
                "version": "==8.2.0",
            },
        },
    }

    pipfile_lock = tmp_path / "Pipfile.lock"
    pipfile_lock.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    parser = PipfileLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "pytest"
    assert dependencies[0].version == "8.2.0"


def test_parse_uses_unknown_when_version_is_missing(
    tmp_path,
):
    data = {
        "default": {
            "requests": {},
        },
    }

    pipfile_lock = tmp_path / "Pipfile.lock"
    pipfile_lock.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    parser = PipfileLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "requests"
    assert dependencies[0].version == "unknown"


def test_parse_deduplicates_dependencies_case_insensitively(
    tmp_path,
):
    data = {
        "default": {
            "Requests": {
                "version": "==2.31.0",
            },
        },
        "develop": {
            "requests": {
                "version": "==2.32.0",
            },
        },
    }

    pipfile_lock = tmp_path / "Pipfile.lock"
    pipfile_lock.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    parser = PipfileLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "Requests"
    assert dependencies[0].version == "2.31.0"


def test_parse_keeps_distinct_dependencies(
    tmp_path,
):
    data = {
        "default": {
            "requests": {
                "version": "==2.31.0",
            },
        },
        "develop": {
            "pytest": {
                "version": "==8.2.0",
            },
        },
    }

    pipfile_lock = tmp_path / "Pipfile.lock"
    pipfile_lock.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    parser = PipfileLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 2

    dependency_names = {dependency.name for dependency in dependencies}

    assert dependency_names == {
        "requests",
        "pytest",
    }
