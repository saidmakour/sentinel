from pathlib import Path

from sentinel.plugins.go.parsers.go_mod_parser import GoModParser
from sentinel.plugins.go.scanner import GoScanner


class TestGoScanner:
    def test_default_parser_is_go_mod_parser(self) -> None:
        scanner = GoScanner()

        assert len(scanner.parsers) == 2
        assert isinstance(
            scanner.parsers[0],
            GoModParser,
        )

    def test_scans_go_mod(
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
)
""",
            encoding="utf-8",
        )

        dependencies = GoScanner().scan(tmp_path)

        assert len(dependencies) == 2

        assert dependencies[0].name == "github.com/gin-gonic/gin"
        assert dependencies[0].version == "v1.10.0"

        assert dependencies[1].name == "golang.org/x/crypto"
        assert dependencies[1].version == "v0.27.0"
