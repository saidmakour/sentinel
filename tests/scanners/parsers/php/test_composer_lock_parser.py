from pathlib import Path

from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.php.parsers.composer_lock_parser import (
    ComposerLockParser,
)


def test_supports(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "composer.lock",
        "{}",
    )

    parser = ComposerLockParser()

    assert parser.supports(temp_project)


def test_not_supports(
    temp_project: Path,
) -> None:
    parser = ComposerLockParser()

    assert not parser.supports(temp_project)


def test_parse_empty(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "composer.lock",
        """
{
}
""",
    )

    parser = ComposerLockParser()

    deps = parser.parse(temp_project)

    assert deps == []


def test_parse_packages(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "composer.lock",
        """
{
    "packages": [
        {
            "name": "symfony/console",
            "version": "v7.2.1"
        }
    ]
}
""",
    )

    parser = ComposerLockParser()

    deps = parser.parse(temp_project)

    assert len(deps) == 1

    dep = deps[0]

    assert dep.name == "symfony/console"
    assert dep.version == "v7.2.1"
    assert dep.ecosystem == Ecosystem.COMPOSER.value
    assert dep.source == "composer.lock"


def test_parse_multiple_packages(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "composer.lock",
        """
{
    "packages": [
        {
            "name": "symfony/console",
            "version": "v7.2.1"
        },
        {
            "name": "monolog/monolog",
            "version": "3.9.0"
        }
    ]
}
""",
    )

    parser = ComposerLockParser()

    deps = parser.parse(temp_project)

    assert len(deps) == 2

    names = {dep.name for dep in deps}

    assert names == {
        "symfony/console",
        "monolog/monolog",
    }


def test_ignore_invalid_package(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "composer.lock",
        """
{
    "packages": [
        {
            "name": "symfony/console",
            "version": "v7.2.1"
        },
        {
            "name": "invalid-package"
        },
        {
            "version": "1.0.0"
        }
    ]
}
""",
    )

    parser = ComposerLockParser()

    deps = parser.parse(temp_project)

    assert len(deps) == 1
    assert deps[0].name == "symfony/console"
