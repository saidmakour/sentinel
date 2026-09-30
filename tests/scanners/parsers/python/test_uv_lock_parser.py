from pathlib import Path

from sentinel.plugins.python.parsers.uv_lock_parser import UVLockParser


def test_supports_returns_false_when_uv_lock_missing(
    temp_project,
):

    parser = UVLockParser()

    assert parser.supports(temp_project) is False


def test_supports_returns_true_when_uv_lock_exists(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "uv.lock",
        "",
    )

    parser = UVLockParser()

    assert parser.supports(temp_project) is True


def test_parse_package(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "uv.lock",
        """
[[package]]
name = "requests"
version = "2.32.3"
""",
    )

    parser = UVLockParser()

    result = parser.parse(temp_project)

    assert len(result) == 1

    dependency = result[0]

    assert dependency.name == "requests"
    assert dependency.version == "2.32.3"


def test_parse_multiple_packages(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "uv.lock",
        """
[[package]]
name = "requests"
version = "2.32.3"

[[package]]
name = "flask"
version = "3.0.0"
""",
    )

    parser = UVLockParser()

    result = parser.parse(temp_project)

    names = {dep.name for dep in result}

    assert names == {
        "requests",
        "flask",
    }


def test_ignore_package_without_version(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "uv.lock",
        """
[[package]]
name = "requests"

[[package]]
name = "flask"
version = "3.0.0"
""",
    )

    parser = UVLockParser()

    result = parser.parse(temp_project)

    assert len(result) == 1

    dependency = result[0]

    assert dependency.name == "flask"


def test_ignore_package_without_name(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "uv.lock",
        """
[[package]]
version = "2.32.3"

[[package]]
name = "requests"
version = "2.32.3"
""",
    )

    parser = UVLockParser()

    result = parser.parse(temp_project)

    assert len(result) == 1

    assert result[0].name == "requests"


def test_ignore_duplicate_packages(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "uv.lock",
        """
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "requests"
version = "2.32.3"
""",
    )

    parser = UVLockParser()

    result = parser.parse(temp_project)

    assert len(result) == 1

    dependency = result[0]

    assert dependency.version == "2.31.0"


def test_dependency_metadata(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "uv.lock",
        """
[[package]]
name = "requests"
version = "2.32.3"
""",
    )

    parser = UVLockParser()

    result = parser.parse(temp_project)

    dependency = result[0]

    assert dependency.source == "uv.lock"
    assert dependency.ecosystem == "PyPI"


def test_parse_ignores_root_project(
    tmp_path: Path,
) -> None:
    lock_file = tmp_path / "uv.lock"

    lock_file.write_text(
        """
[[package]]
name = "sentinel"
version = "1.0.0"
source = { editable = "." }

[[package]]
name = "fastapi"
version = "0.116.1"
source = { registry = "https://pypi.org/simple" }
""",
        encoding="utf-8",
    )

    parser = UVLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "fastapi"
    assert dependencies[0].version == "0.116.1"


def test_parse_keeps_non_root_editable_package(
    tmp_path: Path,
) -> None:
    lock_file = tmp_path / "uv.lock"

    lock_file.write_text(
        """
[[package]]
name = "sentinel"
version = "1.0.0"
source = { editable = "." }

[[package]]
name = "my-local-package"
version = "1.2.3"
source = { editable = "../my-local-package" }
""",
        encoding="utf-8",
    )

    parser = UVLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "my-local-package"
    assert dependencies[0].version == "1.2.3"
