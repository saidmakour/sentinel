from unittest.mock import MagicMock

from sentinel.plugins.php.scanner import PHPScanner
from sentinel.scanners.parsers.base_parser import BaseParser


def test_scan_composer_lock(
    temp_project,
    create_file,
):

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

    scanner = PHPScanner()

    deps = scanner.scan(temp_project)

    assert len(deps) == 1
    assert deps[0].name == "symfony/console"
    assert deps[0].version == "v7.2.1"


def test_scan_composer_json(
    temp_project,
    create_file,
):

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
    scanner = PHPScanner()

    deps = scanner.scan(temp_project)

    assert len(deps) == 1
    assert deps[0].version == "^7.2"


def test_lock_file_has_priority(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "composer.json",
        """
{
    "require": {
        "symfony/console": "^7.2",
        "monolog/monolog": "^3.9"
    }
}
""",
    )

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

    scanner = PHPScanner()
    deps = scanner.scan(temp_project)

    assert len(deps) == 2

    versions = {dep.name: dep.version for dep in deps}

    assert versions["symfony/console"] == "v7.2.1"
    assert versions["monolog/monolog"] == "^3.9"


def test_php_scanner_accepts_custom_parsers() -> None:
    parser = MagicMock(spec=BaseParser)

    scanner = PHPScanner(parsers=[parser])

    assert scanner.parsers == [parser]


def test_php_scanner_uses_default_parsers() -> None:
    scanner = PHPScanner()

    assert len(scanner.parsers) == 2
