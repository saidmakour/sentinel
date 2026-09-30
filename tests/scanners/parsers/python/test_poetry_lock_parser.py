from sentinel.plugins.python.parsers.poetry_lock_parser import PoetryLockParser


def test_supports_returns_false_when_poetry_lock_missing(
    temp_project,
):

    parser = PoetryLockParser()

    assert parser.supports(temp_project) is False


def test_supports_returns_true_when_poetry_lock_exists(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "poetry.lock",
        "",
    )

    parser = PoetryLockParser()

    assert parser.supports(temp_project) is True


def test_parse_package(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "poetry.lock",
        """
[[package]]
name = "requests"
version = "2.32.3"
""",
    )

    parser = PoetryLockParser()

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
        "poetry.lock",
        """
[[package]]
name = "requests"
version = "2.32.3"

[[package]]
name = "flask"
version = "3.0.0"
""",
    )

    parser = PoetryLockParser()

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
        "poetry.lock",
        """
[[package]]
name = "requests"

[[package]]
name = "flask"
version = "3.0.0"
""",
    )

    parser = PoetryLockParser()

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
        "poetry.lock",
        """
[[package]]
version = "2.32.3"

[[package]]
name = "requests"
version = "2.32.3"
""",
    )

    parser = PoetryLockParser()

    result = parser.parse(temp_project)

    assert len(result) == 1

    assert result[0].name == "requests"


def test_ignore_duplicate_packages(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "poetry.lock",
        """
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "requests"
version = "2.32.3"
""",
    )

    parser = PoetryLockParser()

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
        "poetry.lock",
        """
[[package]]
name = "requests"
version = "2.32.3"
""",
    )

    parser = PoetryLockParser()

    result = parser.parse(temp_project)

    dependency = result[0]

    assert dependency.source == "poetry.lock"
    assert dependency.ecosystem == "PyPI"
