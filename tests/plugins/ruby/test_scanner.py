from sentinel.plugins.ruby.parsers.gemfile_lock_parser import GemfileLockParser
from sentinel.plugins.ruby.parsers.gemfile_parser import GemfileParser
from sentinel.plugins.ruby.scanner import RubyScanner


def test_scanner_uses_default_parsers() -> None:
    scanner = RubyScanner()

    assert len(scanner.parsers) == 2
    assert isinstance(scanner.parsers[0], GemfileLockParser)
    assert isinstance(scanner.parsers[1], GemfileParser)


def test_scanner_prioritizes_gemfile_lock() -> None:
    scanner = RubyScanner()

    assert isinstance(
        scanner.parsers[0],
        GemfileLockParser,
    )


def test_scanner_accepts_custom_parsers() -> None:
    parser = GemfileParser()

    scanner = RubyScanner(
        parsers=[parser],
    )

    assert scanner.parsers == [parser]
