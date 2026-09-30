from pathlib import Path

from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.php.parsers.composer_json_parser import (
    ComposerJsonParser,
)


def test_supports(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "composer.json",
        "{}",
    )

    parser = ComposerJsonParser()

    assert parser.supports(temp_project)


def test_not_supports(
    temp_project: Path,
) -> None:
    parser = ComposerJsonParser()

    assert not parser.supports(temp_project)


def test_parse_empty(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "composer.json",
        """
{
}
""",
    )

    parser = ComposerJsonParser()

    deps = parser.parse(temp_project)

    assert deps == []


def test_parse_require(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "composer.json",
        """
{
    "require": {
        "symfony/console": "^7.2"
    }
}
""",
    )

    parser = ComposerJsonParser()

    deps = parser.parse(temp_project)

    assert len(deps) == 1

    dep = deps[0]

    assert dep.name == "symfony/console"
    assert dep.version == "^7.2"
    assert dep.ecosystem == Ecosystem.COMPOSER.value
    assert dep.source == "composer.json"


def test_parse_require_dev(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "composer.json",
        """
{
    "require-dev": {
        "phpunit/phpunit": "^12"
    }
}
""",
    )

    parser = ComposerJsonParser()

    deps = parser.parse(temp_project)

    assert len(deps) == 1

    dep = deps[0]

    assert dep.name == "phpunit/phpunit"
    assert dep.version == "^12"


def test_parse_require_and_require_dev(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "composer.json",
        """
{
    "require": {
        "symfony/console": "^7.2",
        "monolog/monolog": "^3.9"
    },
    "require-dev": {
        "phpunit/phpunit": "^12"
    }
}
""",
    )

    parser = ComposerJsonParser()

    deps = parser.parse(temp_project)

    assert len(deps) == 3

    names = {dep.name for dep in deps}

    assert names == {
        "symfony/console",
        "monolog/monolog",
        "phpunit/phpunit",
    }


def test_ignore_invalid_dependency_values(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "composer.json",
        """
{
    "require": {
        "symfony/console": "^7.2",
        "invalid/package": 123,
        "another/package": null
    }
}
""",
    )

    parser = ComposerJsonParser()

    deps = parser.parse(temp_project)

    assert len(deps) == 1
    assert deps[0].name == "symfony/console"
