from pathlib import Path
from unittest.mock import MagicMock

from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.node.scanner import NodeScanner
from sentinel.scanners.parsers.base_parser import BaseParser


def test_scan_package_lock_file(
    temp_project,
    create_file,
):

    create_file(
        temp_project,
        "package-lock.json",
        """
{
  "name": "mon-site-web",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "mon-site-web",
      "version": "1.0.0"
    },
    "node_modules/express": {
      "version": "4.21.0"
    }
  }
}
""",
    )

    scanner = NodeScanner()
    deps = scanner.scan(temp_project)

    assert len(deps) == 1
    assert deps[0].name == "express"
    assert deps[0].version == "4.21.0"
    assert deps[0].ecosystem == Ecosystem.NPM.value


def test_lock_file_has_priority(
    temp_project,
    create_file,
) -> None:

    create_file(
        temp_project,
        "package.json",
        """
{
  "dependencies": {
    "express": "^4.21.0",
    "lodash": "^4.17.21"
  }
}
""",
    )
    create_file(
        temp_project,
        "package-lock.json",
        """
{
  "packages": {
    "node_modules/express": {
      "version": "4.21.2"
    }
  }
}
""",
    )

    scanner = NodeScanner()
    deps = scanner.scan(temp_project)

    assert len(deps) == 2

    versions = {d.name: d.version for d in deps}

    assert versions["express"] == "4.21.2"
    assert versions["lodash"] == "^4.17.21"


def create_package_json(
    project_path: Path,
) -> None:
    file = project_path / "package.json"

    file.write_text(
        """
        {
            "name": "example-project",
            "version": "1.0.0",
            "dependencies": {
                "axios": "^1.7.0",
                "lodash": "^4.17.0"
            }
        }
        """,
        encoding="utf-8",
    )


def create_package_lock(
    project_path: Path,
) -> None:
    file = project_path / "package-lock.json"

    file.write_text(
        """
        {
            "name": "example-project",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "example-project",
                    "version": "1.0.0"
                },
                "node_modules/axios": {
                    "version": "1.7.9"
                },
                "node_modules/lodash": {
                    "version": "4.17.21"
                }
            }
        }
        """,
        encoding="utf-8",
    )


def test_node_scanner_prefers_package_lock_versions(
    tmp_path: Path,
) -> None:
    create_package_json(tmp_path)
    create_package_lock(tmp_path)

    scanner = NodeScanner()

    dependencies = scanner.scan(tmp_path)

    dependencies_by_name = {
        dependency.name: dependency for dependency in dependencies
    }

    assert dependencies_by_name.keys() == {
        "axios",
        "lodash",
    }

    axios = dependencies_by_name["axios"]

    assert axios.version == "1.7.9"
    assert axios.ecosystem == Ecosystem.NPM.value
    assert axios.source == "package-lock.json"
    assert axios.priority == (DependencySourcePriority.LOCK_FILE)

    lodash = dependencies_by_name["lodash"]

    assert lodash.version == "4.17.21"
    assert lodash.ecosystem == Ecosystem.NPM.value
    assert lodash.source == "package-lock.json"
    assert lodash.priority == (DependencySourcePriority.LOCK_FILE)


def create_2_package_json(
    project_path: Path,
) -> None:
    file = project_path / "package.json"

    file.write_text(
        """
        {
            "name": "example-project",
            "version": "1.0.0",
            "dependencies": {
                "axios": "^1.7.0",
                "lodash": "^4.17.0"
            }
        }
        """,
        encoding="utf-8",
    )


def create_yarn_lock(
    project_path: Path,
) -> None:
    file = project_path / "yarn.lock"

    file.write_text(
        """
        # yarn lockfile v1

        axios@^1.7.0:
          version "1.7.9"
          resolved "https://registry.yarnpkg.com/axios/-/axios-1.7.9.tgz"

        lodash@^4.17.0:
          version "4.17.21"
          resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
        """,
        encoding="utf-8",
    )


def test_node_scanner_prefers_yarn_lock_versions(
    tmp_path: Path,
) -> None:
    create_2_package_json(tmp_path)
    create_yarn_lock(tmp_path)

    scanner = NodeScanner()

    dependencies = scanner.scan(tmp_path)

    dependencies_by_name = {
        dependency.name: dependency for dependency in dependencies
    }

    assert dependencies_by_name.keys() == {
        "axios",
        "lodash",
    }

    axios = dependencies_by_name["axios"]

    assert axios.version == "1.7.9"
    assert axios.ecosystem == Ecosystem.NPM.value
    assert axios.source == "yarn.lock"
    assert axios.priority == (DependencySourcePriority.LOCK_FILE)

    lodash = dependencies_by_name["lodash"]

    assert lodash.version == "4.17.21"
    assert lodash.ecosystem == Ecosystem.NPM.value
    assert lodash.source == "yarn.lock"
    assert lodash.priority == (DependencySourcePriority.LOCK_FILE)


def test_node_scanner_accepts_custom_parsers() -> None:
    parser = MagicMock(spec=BaseParser)

    scanner = NodeScanner(parsers=[parser])

    assert scanner.parsers == [parser]


def test_node_scanner_uses_default_parsers() -> None:
    scanner = NodeScanner()

    assert len(scanner.parsers) == 4
