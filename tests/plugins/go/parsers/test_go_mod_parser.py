from pathlib import Path

from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.go.parsers.go_mod_parser import GoModParser


class TestGoModParser:
    def test_supports_go_mod(
        self,
        tmp_path: Path,
    ) -> None:
        (tmp_path / "go.mod").write_text(
            "module example.com/project\n",
            encoding="utf-8",
        )

        parser = GoModParser()

        assert parser.supports(tmp_path) is True

    def test_does_not_support_project_without_go_mod(
        self,
        tmp_path: Path,
    ) -> None:
        parser = GoModParser()

        assert parser.supports(tmp_path) is False

    def test_parses_single_require(
        self,
        tmp_path: Path,
    ) -> None:
        (tmp_path / "go.mod").write_text(
            """\
module example.com/project

go 1.23

require github.com/gin-gonic/gin v1.10.0
""",
            encoding="utf-8",
        )

        dependencies = GoModParser().parse(tmp_path)

        assert len(dependencies) == 1

        dependency = dependencies[0]

        assert dependency.name == "github.com/gin-gonic/gin"
        assert dependency.version == "v1.10.0"
        assert dependency.ecosystem == Ecosystem.GOLANG
        assert dependency.source == "go.mod"
        assert dependency.priority == DependencySourcePriority.MANIFEST

    def test_parses_require_block(
        self,
        tmp_path: Path,
    ) -> None:
        (tmp_path / "go.mod").write_text(
            """\
module example.com/project

go 1.23

require (
    github.com/gin-gonic/gin v1.10.0
    golang.org/x/crypto v0.27.0
    github.com/stretchr/testify v1.9.0
)
""",
            encoding="utf-8",
        )

        dependencies = GoModParser().parse(tmp_path)

        assert len(dependencies) == 3

        assert dependencies[0].name == "github.com/gin-gonic/gin"
        assert dependencies[0].version == "v1.10.0"

        assert dependencies[1].name == "golang.org/x/crypto"
        assert dependencies[1].version == "v0.27.0"

        assert dependencies[2].name == "github.com/stretchr/testify"
        assert dependencies[2].version == "v1.9.0"

        assert all(
            dependency.ecosystem == Ecosystem.GOLANG
            for dependency in dependencies
        )

    def test_parses_direct_and_indirect_dependencies(
        self,
        tmp_path: Path,
    ) -> None:
        (tmp_path / "go.mod").write_text(
            """\
module example.com/project

require (
    github.com/gin-gonic/gin v1.10.0
    golang.org/x/crypto v0.27.0 // indirect
)
""",
            encoding="utf-8",
        )

        dependencies = GoModParser().parse(tmp_path)

        assert len(dependencies) == 2

        assert dependencies[0].name == "github.com/gin-gonic/gin"
        assert dependencies[0].version == "v1.10.0"

        assert dependencies[1].name == "golang.org/x/crypto"
        assert dependencies[1].version == "v0.27.0"

    def test_ignores_comments_and_empty_lines(
        self,
        tmp_path: Path,
    ) -> None:
        (tmp_path / "go.mod").write_text(
            """\
module example.com/project

// This is a comment.

require (
    // Another comment

    github.com/gin-gonic/gin v1.10.0

    // More comments
    golang.org/x/crypto v0.27.0
)
""",
            encoding="utf-8",
        )

        dependencies = GoModParser().parse(tmp_path)

        assert len(dependencies) == 2

    def test_ignores_invalid_require_lines(
        self,
        tmp_path: Path,
    ) -> None:
        (tmp_path / "go.mod").write_text(
            """\
module example.com/project

require (
    github.com/gin-gonic/gin v1.10.0
    invalid-line
    another-invalid-line
)
""",
            encoding="utf-8",
        )

        dependencies = GoModParser().parse(tmp_path)

        assert len(dependencies) == 1
        assert dependencies[0].name == "github.com/gin-gonic/gin"

    def test_parses_require_with_inline_comment(
        self,
        tmp_path: Path,
    ) -> None:
        (tmp_path / "go.mod").write_text(
            """\
module example.com/project

require github.com/gin-gonic/gin v1.10.0 // indirect
""",
            encoding="utf-8",
        )

        dependencies = GoModParser().parse(tmp_path)

        assert len(dependencies) == 1

        assert dependencies[0].name == "github.com/gin-gonic/gin"
        assert dependencies[0].version == "v1.10.0"

    def test_returns_empty_list_for_empty_go_mod(
        self,
        tmp_path: Path,
    ) -> None:
        (tmp_path / "go.mod").write_text(
            "",
            encoding="utf-8",
        )

        dependencies = GoModParser().parse(tmp_path)

        assert dependencies == []

    def test_returns_empty_list_without_require_directives(
        self,
        tmp_path: Path,
    ) -> None:
        (tmp_path / "go.mod").write_text(
            """\
module example.com/project

go 1.23
""",
            encoding="utf-8",
        )

        dependencies = GoModParser().parse(tmp_path)

        assert dependencies == []
