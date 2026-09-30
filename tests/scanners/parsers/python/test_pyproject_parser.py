from pathlib import Path
from typing import Any

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.plugins.python.parsers.pyproject_parser import PyProjectParser


# 1
def test_supports_returns_false_when_pyproject_missing(
    temp_project,
):

    parser = PyProjectParser()

    assert parser.supports(temp_project) is False


# 2
def test_supports_returns_true_when_pyproject_exists(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "pyproject.toml",
        "",
    )

    parser = PyProjectParser()

    assert parser.supports(temp_project) is True


# 3


# 4
def test_parse_poetry_dependencies(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "pyproject.toml",
        """
[tool.poetry.dependencies]
python = "^3.12"
requests = "^2.32"
flask = "3.0"
""",
    )

    parser = PyProjectParser()

    result = parser.parse(temp_project)

    names = {dep.name for dep in result}

    assert "requests" in names
    assert "flask" in names
    assert "python" not in names


# 5
def test_sets_source_and_ecosystem(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "pyproject.toml",
        """
[project]
dependencies = [
    "requests==2.32.3",
]
""",
    )

    parser = PyProjectParser()

    result = parser.parse(temp_project)

    dependency = result[0]

    assert dependency.source == "pyproject.toml"
    assert dependency.ecosystem == "PyPI"


# 6
def test_ignore_optional_dependencies(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "pyproject.toml",
        """
[project.optional-dependencies]
dev = [
    "pytest",
]
""",
    )

    parser = PyProjectParser()

    result = parser.parse(temp_project)

    assert result == []


# 7
def test_parse_project_without_dependencies(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "pyproject.toml",
        """
[project]
name = "my-project"
version = "1.0.0"
""",
    )

    parser = PyProjectParser()

    result = parser.parse(temp_project)

    assert result == []


# 8
def test_parse_dependency_without_version(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "pyproject.toml",
        """
[project]
dependencies = [
    "requests",
]
""",
    )

    parser = PyProjectParser()

    result = parser.parse(temp_project)

    assert len(result) == 1

    dependency = result[0]

    assert dependency.name == "requests"
    assert dependency.version == "unknown"


def write_pyproject(
    tmp_path: Path,
    content: str,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        content,
        encoding="utf-8",
    )


def test_supports_returns_true_when_file_exists(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        """
        [project]
        name = "sentinel"
        """,
    )

    parser = PyProjectParser()

    assert parser.supports(tmp_path) is True


def test_supports_returns_false_when_file_does_not_exist(
    tmp_path,
):
    parser = PyProjectParser()

    assert parser.supports(tmp_path) is False


def test_parse_all_supported_requirement_separators(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        """
        [project]
        dependencies = [
            "package1==1.0.0",
            "package2>=2.0.0",
            "package3<=3.0.0",
            "package4~=4.0.0",
            "package5^5.0.0",
        ]
        """,
    )

    parser = PyProjectParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 5

    versions = {
        dependency.name: dependency.version for dependency in dependencies
    }

    assert versions == {
        "package1": "1.0.0",
        "package2": "2.0.0",
        "package3": "3.0.0",
        "package4": "4.0.0",
        "package5": "5.0.0",
    }


def test_parse_poetry_dependency_with_missing_version(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        """
        [tool.poetry.dependencies]
        requests = {}
        """,
    )

    parser = PyProjectParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "requests"
    assert dependencies[0].version == "unknown"


def test_parse_deduplicates_dependencies_case_insensitively(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        """
        [project]
        dependencies = [
            "Requests==2.31.0",
        ]

        [tool.poetry.dependencies]
        requests = "^2.32.0"
        """,
    )

    parser = PyProjectParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "Requests"
    assert dependencies[0].version == "2.31.0"


def test_parse_empty_pyproject(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        """
        [project]
        name = "sentinel"
        """,
    )

    parser = PyProjectParser()

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_project_and_poetry_dependencies(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        """
        [project]
        dependencies = [
            "requests==2.31.0",
        ]

        [tool.poetry.dependencies]
        httpx = "^0.27.0"
        """,
    )

    parser = PyProjectParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 2

    names = {dependency.name for dependency in dependencies}

    assert names == {
        "requests",
        "httpx",
    }


def test_parse_poetry_dependency_with_none_version(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        """
        [tool.poetry.dependencies]
        requests = ""
        """,
    )

    parser = PyProjectParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "requests"
    assert dependencies[0].version == ""


def test_clean_version_returns_unknown_for_none():
    parser = PyProjectParser()

    assert parser._clean_version(None) == "unknown"


def test_parse_multiple_project_dependencies_covers_loop_branch(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        """
        [project]
        dependencies = [
            "requests==2.31.0",
            "httpx==0.27.0",
        ]
        """,
    )

    parser = PyProjectParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 2

    assert dependencies[0].name == "requests"
    assert dependencies[0].version == "2.31.0"

    assert dependencies[1].name == "httpx"
    assert dependencies[1].version == "0.27.0"


def test_parse_multiple_poetry_dependencies_covers_loop_branch(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        """
        [tool.poetry.dependencies]
        requests = "^2.31.0"
        httpx = "^0.27.0"
        """,
    )

    parser = PyProjectParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 2

    dependencies_by_name = {
        dependency.name: dependency for dependency in dependencies
    }

    assert dependencies_by_name["requests"].version == "^2.31.0"
    assert dependencies_by_name["httpx"].version == "^0.27.0"


def test_parse_poetry_python_then_dependency_covers_continue_branch(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        """
        [tool.poetry.dependencies]
        python = "^3.12"
        requests = "^2.31.0"
        """,
    )

    parser = PyProjectParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "requests"
    assert dependencies[0].version == "^2.31.0"


def _parse_project_dependencies(
    self,
    data: dict[str, Any],
    dependencies: dict[str, ScannedDependency],
):

    project = data.get("project", {})

    for requirement in project.get(
        "dependencies",
        [],
    ):
        dependency = self._parse_requirement(requirement)

        dependencies.setdefault(
            dependency.name.lower(),
            dependency,
        )
