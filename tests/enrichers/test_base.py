from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enrichers.base import BaseEnricher
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity


class DummyEnricher(BaseEnricher):
    def enrich(
        self,
        vulnerability: VulnerabilityInfo,
    ) -> VulnerabilityInfo:
        return vulnerability


def make_vulnerability() -> VulnerabilityInfo:
    return VulnerabilityInfo(
        identifier="CVE-2026-0001",
        aliases=["CVE-2026-0001"],
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        sources=[Provider.OSV],
        severity=Severity.LOW,
        cvss=3.1,
        summary="Test vulnerability",
    )


def test_enricher_can_be_instantiated() -> None:
    enricher = DummyEnricher()

    assert enricher is not None


def test_enrich_returns_vulnerability() -> None:
    vulnerability = make_vulnerability()

    enricher = DummyEnricher()

    result = enricher.enrich(vulnerability)

    assert result is vulnerability
