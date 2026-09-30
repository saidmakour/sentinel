from sentinel.enums.enricher import Enricher


def test_enricher_values() -> None:
    assert Enricher.KEV.value == "kev"
    assert Enricher.EPSS.value == "epss"


def test_enricher_is_string_enum() -> None:
    assert str(Enricher.KEV) == "kev"
