from pathlib import Path

from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.node.parsers.pnpm_lock_parser import PnpmLockParser


def create_pnpm_lock(
    project_path: Path,
    content: str,
) -> Path:
    file = project_path / "pnpm-lock.yaml"

    file.write_text(
        content,
        encoding="utf-8",
    )

    return file


def test_supports_pnpm_lock(
    tmp_path: Path,
) -> None:
    create_pnpm_lock(
        tmp_path,
        "",
    )

    parser = PnpmLockParser()

    assert parser.supports(tmp_path)


def test_does_not_support_missing_pnpm_lock(
    tmp_path: Path,
) -> None:
    parser = PnpmLockParser()

    assert not parser.supports(tmp_path)


def test_parse_single_dependency(
    tmp_path: Path,
) -> None:
    create_pnpm_lock(
        tmp_path,
        """
        lockfileVersion: '9.0'

        snapshots:
          axios@1.7.9: {}
        """,
    )

    parser = PnpmLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "axios"
    assert dependency.version == "1.7.9"
    assert dependency.ecosystem == Ecosystem.NPM.value
    assert dependency.source == "pnpm-lock.yaml"
    assert dependency.priority == (DependencySourcePriority.LOCK_FILE)


def test_parse_multiple_dependencies(
    tmp_path: Path,
) -> None:
    create_pnpm_lock(
        tmp_path,
        """
        lockfileVersion: '9.0'

        snapshots:
          axios@1.7.9: {}
          lodash@4.17.21: {}
        """,
    )

    parser = PnpmLockParser()

    dependencies = parser.parse(tmp_path)

    dependencies_by_name = {
        dependency.name: dependency for dependency in dependencies
    }

    assert dependencies_by_name.keys() == {
        "axios",
        "lodash",
    }

    assert dependencies_by_name["axios"].version == "1.7.9"
    assert dependencies_by_name["lodash"].version == "4.17.21"


def test_parse_ignores_invalid_package_key(
    tmp_path: Path,
) -> None:
    create_pnpm_lock(
        tmp_path,
        """
        lockfileVersion: '9.0'

        snapshots:
          invalid: {}
          axios@: {}
          "@scope/package@": {}
        """,
    )

    parser = PnpmLockParser()

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_scoped_dependency(
    tmp_path: Path,
) -> None:
    create_pnpm_lock(
        tmp_path,
        """
        lockfileVersion: '9.0'

        snapshots:
          "@angular/core@19.0.0": {}
        """,
    )

    parser = PnpmLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "@angular/core"
    assert dependency.version == "19.0.0"
