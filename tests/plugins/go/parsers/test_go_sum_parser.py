from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.go.parsers.go_sum_parser import GoSumParser


def test_go_sum_parser_file_name() -> None:
    parser = GoSumParser()

    assert parser.FILE == "go.sum"


def test_go_sum_parser_priority() -> None:
    parser = GoSumParser()

    assert parser.PRIORITY == DependencySourcePriority.LOCK_FILE


def test_supports_existing_file(tmp_path: Path) -> None:
    (tmp_path / "go.sum").write_text(
        "github.com/foo/bar v1.2.3 h1:abc\n",
        encoding="utf-8",
    )

    parser = GoSumParser()

    assert parser.supports(tmp_path) is True


def test_supports_missing_file(tmp_path: Path) -> None:
    parser = GoSumParser()

    assert parser.supports(tmp_path) is False


def test_parse_single_dependency(tmp_path: Path) -> None:
    (tmp_path / "go.sum").write_text(
        "github.com/foo/bar v1.2.3 h1:abc\n",
        encoding="utf-8",
    )

    parser = GoSumParser()

    dependencies = parser.parse(tmp_path)

    assert dependencies == [
        ScannedDependency(
            name="github.com/foo/bar",
            version="v1.2.3",
            ecosystem=Ecosystem.GOLANG,
            source="go.sum",
            priority=DependencySourcePriority.LOCK_FILE,
        )
    ]


def test_parse_multiple_dependencies(tmp_path: Path) -> None:
    (tmp_path / "go.sum").write_text(
        "\n".join(
            [
                "github.com/foo/bar v1.2.3 h1:abc",
                "golang.org/x/net v0.25.0 h1:def",
                "golang.org/x/sys v0.20.0 h1:ghi",
            ]
        ),
        encoding="utf-8",
    )

    parser = GoSumParser()

    dependencies = parser.parse(tmp_path)

    assert dependencies == [
        ScannedDependency(
            name="github.com/foo/bar",
            version="v1.2.3",
            ecosystem=Ecosystem.GOLANG,
            source="go.sum",
            priority=DependencySourcePriority.LOCK_FILE,
        ),
        ScannedDependency(
            name="golang.org/x/net",
            version="v0.25.0",
            ecosystem=Ecosystem.GOLANG,
            source="go.sum",
            priority=DependencySourcePriority.LOCK_FILE,
        ),
        ScannedDependency(
            name="golang.org/x/sys",
            version="v0.20.0",
            ecosystem=Ecosystem.GOLANG,
            source="go.sum",
            priority=DependencySourcePriority.LOCK_FILE,
        ),
    ]


def test_parse_go_mod_checksum_entry(tmp_path: Path) -> None:
    (tmp_path / "go.sum").write_text(
        "github.com/foo/bar v1.2.3/go.mod h1:abc\n",
        encoding="utf-8",
    )

    parser = GoSumParser()

    dependencies = parser.parse(tmp_path)

    assert dependencies == [
        ScannedDependency(
            name="github.com/foo/bar",
            version="v1.2.3",
            ecosystem=Ecosystem.GOLANG,
            source="go.sum",
            priority=DependencySourcePriority.LOCK_FILE,
        )
    ]


def test_parse_deduplicates_go_mod_checksum_entry(tmp_path: Path) -> None:
    (tmp_path / "go.sum").write_text(
        "\n".join(
            [
                "github.com/foo/bar v1.2.3 h1:abc",
                "github.com/foo/bar v1.2.3/go.mod h1:def",
            ]
        ),
        encoding="utf-8",
    )

    parser = GoSumParser()

    dependencies = parser.parse(tmp_path)

    assert dependencies == [
        ScannedDependency(
            name="github.com/foo/bar",
            version="v1.2.3",
            ecosystem=Ecosystem.GOLANG,
            source="go.sum",
            priority=DependencySourcePriority.LOCK_FILE,
        )
    ]


def test_parse_ignores_empty_lines(tmp_path: Path) -> None:
    (tmp_path / "go.sum").write_text(
        "\ngithub.com/foo/bar v1.2.3 h1:abc\n\n",
        encoding="utf-8",
    )

    parser = GoSumParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "github.com/foo/bar"


def test_parse_ignores_invalid_lines(tmp_path: Path) -> None:
    (tmp_path / "go.sum").write_text(
        "\n".join(
            [
                "",
                "invalid",
                "only-one-field",
                "github.com/foo/bar",
                "github.com/foo/bar v1.2.3 h1:abc",
            ]
        ),
        encoding="utf-8",
    )

    parser = GoSumParser()

    dependencies = parser.parse(tmp_path)

    assert dependencies == [
        ScannedDependency(
            name="github.com/foo/bar",
            version="v1.2.3",
            ecosystem=Ecosystem.GOLANG,
            source="go.sum",
            priority=DependencySourcePriority.LOCK_FILE,
        )
    ]
