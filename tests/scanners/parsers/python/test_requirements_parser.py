from sentinel.plugins.python.parsers.requirements_parser import (
    RequirementsParser,
)


# 1
def test_supports_returns_false_when_requirements_missing(
    temp_project,
):

    parser = RequirementsParser()

    assert parser.supports(temp_project) is False


# 2
def test_supports_returns_true_when_requirements_exists(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "requirements.txt",
        "",
    )

    parser = RequirementsParser()

    assert parser.supports(temp_project) is True


# 3
def test_parse_empty_file_returns_empty_list(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "requirements.txt",
        "",
    )

    parser = RequirementsParser()

    result = parser.parse(temp_project)

    assert result == []


# 4
def test_parse_exact_version(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "requirements.txt",
        "requests==2.32.3",
    )

    parser = RequirementsParser()

    result = parser.parse(temp_project)

    assert len(result) == 1

    dependency = result[0]

    assert dependency.name == "requests"
    assert dependency.version == "2.32.3"
    assert dependency.ecosystem == "PyPI"
    assert dependency.source == "requirements.txt"


# 5
def test_ignore_comments(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "requirements.txt",
        """
# comment
requests==2.32.3
# another comment
""",
    )

    parser = RequirementsParser()

    result = parser.parse(temp_project)

    assert len(result) == 1

    dependency = result[0]

    assert dependency.name == "requests"
    assert dependency.version == "2.32.3"


# 6
def test_ignore_blank_lines(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "requirements.txt",
        """

requests==2.32.3


flask>=3.0

""",
    )

    parser = RequirementsParser()

    result = parser.parse(temp_project)

    assert len(result) == 2


# 7
def test_ignore_pip_options(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "requirements.txt",
        """
--extra-index-url https://example.com
-r base.txt
requests==2.32.3
""",
    )

    parser = RequirementsParser()

    result = parser.parse(temp_project)

    assert len(result) == 1
    assert result[0].name == "requests"


# 8
def test_ignore_duplicate_dependencies(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "requirements.txt",
        """
requests==2.31.0
requests==2.32.3
""",
    )

    parser = RequirementsParser()

    result = parser.parse(temp_project)

    assert len(result) == 1

    dependency = result[0]

    assert dependency.name == "requests"
    assert dependency.version == "2.31.0"


# 9
def test_parse_dependency_without_version(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "requirements.txt",
        "requests",
    )

    parser = RequirementsParser()

    result = parser.parse(temp_project)

    assert len(result) == 1

    dependency = result[0]

    assert dependency.name == "requests"
    assert dependency.version == "unknown"


def test_supports_returns_true_when_requirements_file_exists(
    tmp_path,
):
    file = tmp_path / "requirements.txt"
    file.write_text(
        "requests==2.31.0\n",
        encoding="utf-8",
    )

    parser = RequirementsParser()

    assert parser.supports(tmp_path) is True


def test_supports_returns_false_when_requirements_file_does_not_exist(
    tmp_path,
):
    parser = RequirementsParser()

    assert parser.supports(tmp_path) is False


def test_parse_requirements_file(
    tmp_path,
):
    file = tmp_path / "requirements.txt"
    file.write_text(
        """
        requests==2.31.0
        httpx>=0.27.0
        packaging~=24.0
        pytest
        """,
        encoding="utf-8",
    )

    parser = RequirementsParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 4

    dependencies_by_name = {
        dependency.name: dependency for dependency in dependencies
    }

    assert dependencies_by_name["requests"].version == "2.31.0"
    assert dependencies_by_name["httpx"].version == "0.27.0"
    assert dependencies_by_name["packaging"].version == "24.0"
    assert dependencies_by_name["pytest"].version == "unknown"


def test_parse_ignores_missing_requirements_file(
    tmp_path,
):
    parser = RequirementsParser()

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_empty_lines_comments_and_options(
    tmp_path,
):
    file = tmp_path / "requirements.txt"
    file.write_text(
        """
        # This is a comment

        -r other-requirements.txt
        --index-url https://pypi.org/simple

        requests==2.31.0
        """,
        encoding="utf-8",
    )

    parser = RequirementsParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "requests"
    assert dependencies[0].version == "2.31.0"


def test_parse_deduplicates_dependencies_case_insensitively(
    tmp_path,
):
    file = tmp_path / "requirements.txt"
    file.write_text(
        """
        Requests==2.31.0
        requests==2.32.0
        """,
        encoding="utf-8",
    )

    parser = RequirementsParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "Requests"
    assert dependencies[0].version == "2.31.0"


def test_parse_line_returns_none_for_empty_line():
    parser = RequirementsParser()

    assert parser._parse_line("") is None
    assert parser._parse_line("   ") is None


def test_parse_line_returns_none_for_comment():
    parser = RequirementsParser()

    assert parser._parse_line("# comment") is None
    assert parser._parse_line("  # comment") is None


def test_parse_line_returns_none_for_option():
    parser = RequirementsParser()

    assert parser._parse_line("-r requirements-dev.txt") is None
    assert parser._parse_line("--index-url https://pypi.org") is None


def test_parse_line_supports_exact_version():
    parser = RequirementsParser()

    dependency = parser._parse_line(
        "requests==2.31.0",
    )

    assert dependency is not None
    assert dependency.name == "requests"
    assert dependency.version == "2.31.0"


def test_parse_line_supports_minimum_version():
    parser = RequirementsParser()

    dependency = parser._parse_line(
        "httpx>=0.27.0",
    )

    assert dependency is not None
    assert dependency.name == "httpx"
    assert dependency.version == "0.27.0"


def test_parse_line_supports_compatible_version():
    parser = RequirementsParser()

    dependency = parser._parse_line(
        "packaging~=24.0",
    )

    assert dependency is not None
    assert dependency.name == "packaging"
    assert dependency.version == "24.0"


def test_parse_line_defaults_to_unknown_version():
    parser = RequirementsParser()

    dependency = parser._parse_line(
        "pytest",
    )

    assert dependency is not None
    assert dependency.name == "pytest"
    assert dependency.version == "unknown"
