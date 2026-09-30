from sentinel.enrichers.epss.enricher import EPSSEnricher
from sentinel.enrichers.kev.enricher import KEVEnricher
from sentinel.enrichers.registry import EnricherRegistry
from sentinel.enrichers.vulncheck_kev.enricher import VulnCheckKEVEnricher
from sentinel.enums.enricher import Enricher


def test_registry_can_be_created() -> None:
    registry = EnricherRegistry()

    assert registry is not None


def test_create_selected_kev_enricher() -> None:
    registry = EnricherRegistry()

    enrichers = registry.create(
        [
            Enricher.KEV,
        ],
    )

    assert len(enrichers) == 1
    assert isinstance(
        enrichers[0],
        KEVEnricher,
    )


def test_create_selected_enrichers() -> None:
    registry = EnricherRegistry()

    enrichers = registry.create(
        [
            Enricher.KEV,
            Enricher.EPSS,
            Enricher.VULNCHECK_KEV,
        ],
    )

    assert len(enrichers) == 3

    assert isinstance(
        enrichers[0],
        KEVEnricher,
    )

    assert isinstance(
        enrichers[1],
        EPSSEnricher,
    )

    assert isinstance(
        enrichers[2],
        VulnCheckKEVEnricher,
    )


def test_create_unknown_enricher_returns_empty() -> None:
    registry = EnricherRegistry()

    enrichers = registry.create(
        [],
    )

    assert enrichers == []
