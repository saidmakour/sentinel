from pathlib import Path

from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.node.parsers.yarn_lock_parser import YarnLockParser


def create_yarn_lock(
    project_path: Path,
    content: str,
) -> Path:
    file = project_path / "yarn.lock"

    file.write_text(
        content,
        encoding="utf-8",
    )

    return file


def test_supports_yarn_lock(
    tmp_path: Path,
) -> None:
    create_yarn_lock(
        tmp_path,
        "",
    )

    parser = YarnLockParser()

    assert parser.supports(tmp_path)


def test_does_not_support_missing_yarn_lock(
    tmp_path: Path,
) -> None:
    parser = YarnLockParser()

    assert not parser.supports(tmp_path)


def test_parse_single_dependency(
    tmp_path: Path,
) -> None:
    create_yarn_lock(
        tmp_path,
        """
        axios@^1.7.0:
          version "1.7.9"
          resolved "https://registry.yarnpkg.com/axios/-/axios-1.7.9.tgz"
        """,
    )

    parser = YarnLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "axios"
    assert dependency.version == "1.7.9"
    assert dependency.ecosystem == Ecosystem.NPM.value
    assert dependency.source == "yarn.lock"
    assert dependency.priority == (DependencySourcePriority.LOCK_FILE)


def test_parse_multiple_dependencies(
    tmp_path: Path,
) -> None:
    create_yarn_lock(
        tmp_path,
        """
        axios@^1.7.0:
          version "1.7.9"

        lodash@^4.17.0:
          version "4.17.21"
        """,
    )

    parser = YarnLockParser()

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


def test_parse_multiple_selectors_for_same_dependency(
    tmp_path: Path,
) -> None:
    create_yarn_lock(
        tmp_path,
        """
        axios@^1.7.0, axios@^1.8.0:
          version "1.8.0"
        """,
    )

    parser = YarnLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 2

    assert all(dependency.name == "axios" for dependency in dependencies)

    assert all(dependency.version == "1.8.0" for dependency in dependencies)


def test_parse_ignores_entry_without_version(
    tmp_path: Path,
) -> None:
    create_yarn_lock(
        tmp_path,
        """
        axios@^1.7.0:
          resolved "https://registry.yarnpkg.com/axios/-/axios.tgz"
        """,
    )

    parser = YarnLockParser()

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_unrelated_lines(
    tmp_path: Path,
) -> None:
    create_yarn_lock(
        tmp_path,
        """
        # yarn lockfile v1

        axios@^1.7.0:
          version "1.7.9"
          resolved "https://registry.yarnpkg.com/axios/-/axios.tgz"
          integrity sha512-example
        """,
    )

    parser = YarnLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    assert dependencies[0].name == "axios"
    assert dependencies[0].version == "1.7.9"
