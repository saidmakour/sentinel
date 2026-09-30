from pathlib import Path

from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.node.parsers.package_json_parser import PackageJsonParser


def test_supports(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "package.json",
        "{}",
    )

    parser = PackageJsonParser()

    assert parser.supports(temp_project)


def test_not_supports(
    temp_project: Path,
) -> None:
    parser = PackageJsonParser()

    assert not parser.supports(temp_project)


def test_parse_empty(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "package.json",
        """
{
}
""",
    )

    parser = PackageJsonParser()

    deps = parser.parse(temp_project)

    assert deps == []


def test_parse_dependencies(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "package.json",
        """
{
    "dependencies": {
        "express": "^4.21.0",
        "lodash": "~4.17.21"
    }
}
""",
    )

    parser = PackageJsonParser()

    deps = parser.parse(temp_project)

    assert len(deps) == 2

    assert deps[0].ecosystem == Ecosystem.NPM.value
    assert deps[0].source == "package.json"

    names = {d.name for d in deps}

    assert names == {
        "express",
        "lodash",
    }


def test_parse_dev_dependencies(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "package.json",
        """
{
    "devDependencies": {
        "vitest": "^3.2.4",
        "eslint": "^9.0.0"
    }
}
""",
    )

    parser = PackageJsonParser()

    deps = parser.parse(temp_project)

    assert len(deps) == 2

    names = {d.name for d in deps}

    assert names == {
        "vitest",
        "eslint",
    }


def test_parse_dependencies_and_dev_dependencies(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "package.json",
        """
{
    "dependencies": {
        "express": "^4.21.0"
    },
    "devDependencies": {
        "vitest": "^3.2.4"
    }
}
""",
    )

    parser = PackageJsonParser()

    deps = parser.parse(temp_project)

    assert len(deps) == 2

    names = {d.name for d in deps}

    assert names == {
        "express",
        "vitest",
    }


def test_ignore_invalid_dependency_values(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "package.json",
        """
{
    "dependencies": {
        "express": "^4.21.0",
        "invalid": {
            "version": "1.0.0"
        }
    }
}
""",
    )

    parser = PackageJsonParser()

    deps = parser.parse(temp_project)

    assert len(deps) == 1
    assert deps[0].name == "express"
