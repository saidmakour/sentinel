from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.go.plugin import GoPlugin
from sentinel.plugins.go.scanner import GoScanner
from sentinel.plugins.go.version_comparator import GoVersionComparator


class TestGoPlugin:
    def test_name(self) -> None:
        assert GoPlugin().name == "go"

    def test_languages(self) -> None:
        assert GoPlugin().languages == ("go",)

    def test_scanners(self) -> None:
        scanners = GoPlugin().scanners

        assert set(scanners) == {"go"}

        definition = scanners["go"]

        assert definition.scanner is GoScanner
        assert definition.languages == ("go",)

    def test_comparators(self) -> None:
        comparators = GoPlugin().comparators

        assert set(comparators) == {Ecosystem.GOLANG}
        assert isinstance(
            comparators[Ecosystem.GOLANG],
            GoVersionComparator,
        )
