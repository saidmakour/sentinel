from unittest.mock import MagicMock

from sentinel.scanners.base import BaseScanner
from sentinel.scanners.definition import ScannerDefinition
from sentinel.scanners.parsers.base_parser import BaseParser


class DumnyScanner(BaseScanner):
    pass


def test_scanner_definition_can_be_created() -> None:
    parser = MagicMock(spec=BaseParser)

    definition = ScannerDefinition(
        scanner=DumnyScanner,
        parsers=(parser,),
        languages=("dumny",),
    )

    assert definition.scanner is DumnyScanner
    assert definition.parsers == (parser,)


def test_scanner_definition_accepts_multiple_parsers() -> None:
    first_parser = MagicMock(spec=BaseParser)
    second_parser = MagicMock(spec=BaseParser)

    definition = ScannerDefinition(
        scanner=DumnyScanner,
        parsers=(first_parser, second_parser),
        languages=("dumny",),
    )

    assert definition.parsers == (
        first_parser,
        second_parser,
    )


def test_scanner_definition_is_immutable() -> None:
    parser = MagicMock(spec=BaseParser)

    definition = ScannerDefinition(
        scanner=DumnyScanner,
        parsers=(parser,),
        languages=("dumny",),
    )

    try:
        definition.scanner = DumnyScanner
    except AttributeError:
        pass
    else:
        raise AssertionError("ScannerDefinition should be immutable")
