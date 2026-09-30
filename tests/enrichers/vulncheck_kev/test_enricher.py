from datetime import datetime
from unittest.mock import Mock

from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enrichers.vulncheck_kev.enricher import VulnCheckKEVEnricher
from sentinel.enrichers.vulncheck_kev.models import VulnCheckKEVVulnerability
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.enums.vulnerability_status import VulnerabilityStatus


def make_finding(
    identifier: str = "CVE-2025-0001",
) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        dependency_name="example",
        dependency_version="1.0.0",
        ecosystem=Ecosystem.PYPI,
        identifier=identifier,
        aliases=[],
        sources=[Provider.OSV],
        summary="Example vulnerability",
        severity=Severity.HIGH,
        cvss=7.5,
        status=VulnerabilityStatus.UNKNOWN,
    )


def make_vulnerability(
    cve_ids: list[str] | None = None,
) -> VulnCheckKEVVulnerability:
    return VulnCheckKEVVulnerability(
        cve_ids=cve_ids or ["CVE-2025-0001"],
        vendor="Example Vendor",
        product="Example Product",
        short_description="Example vulnerability",
        vulnerability_name="Example Vulnerability",
        required_action="Apply the vendor patch.",
        known_ransomware="Known",
        reported_exploited_by_canaries=True,
        date_added=datetime(2025, 1, 10, 12, 30),
        cisa_date_added=datetime(2025, 1, 11, 8, 15),
        due_date=datetime(2025, 2, 10, 0, 0),
    )


def test_enricher_does_nothing_when_catalog_is_empty() -> None:
    client = Mock()
    client.load.return_value = {}

    finding = make_finding()

    enricher = VulnCheckKEVEnricher(client=client)

    enricher.enrich([finding])

    assert finding.identifier == "CVE-2025-0001"
    client.load.assert_called_once_with()


def test_enricher_does_nothing_when_cve_is_not_found() -> None:
    client = Mock()
    client.load.return_value = {
        "CVE-2025-0002": make_vulnerability(
            ["CVE-2025-0002"],
        ),
    }

    finding = make_finding()

    enricher = VulnCheckKEVEnricher(client=client)

    enricher.enrich([finding])

    assert finding.identifier == "CVE-2025-0001"
    client.load.assert_called_once_with()


def test_enricher_processes_matching_cve() -> None:
    vulnerability = make_vulnerability()

    client = Mock()
    client.load.return_value = {
        "CVE-2025-0001": vulnerability,
    }

    finding = make_finding()

    enricher = VulnCheckKEVEnricher(client=client)

    enricher.enrich([finding])

    assert finding.identifier == "CVE-2025-0001"
    client.load.assert_called_once_with()


def test_enricher_processes_multiple_findings() -> None:
    first = make_finding("CVE-2025-0001")
    second = make_finding("CVE-2025-0002")

    client = Mock()
    client.load.return_value = {
        "CVE-2025-0001": make_vulnerability(
            ["CVE-2025-0001"],
        ),
        "CVE-2025-0002": make_vulnerability(
            ["CVE-2025-0002"],
        ),
    }

    enricher = VulnCheckKEVEnricher(client=client)

    enricher.enrich(
        [
            first,
            second,
        ],
    )

    assert first.identifier == "CVE-2025-0001"
    assert second.identifier == "CVE-2025-0002"
    client.load.assert_called_once_with()


def test_enricher_handles_multiple_cves_in_catalog_entry() -> None:
    vulnerability = make_vulnerability(
        [
            "CVE-2025-0001",
            "CVE-2025-0002",
        ],
    )

    client = Mock()
    client.load.return_value = {
        "CVE-2025-0001": vulnerability,
        "CVE-2025-0002": vulnerability,
    }

    first = make_finding("CVE-2025-0001")
    second = make_finding("CVE-2025-0002")

    enricher = VulnCheckKEVEnricher(client=client)

    enricher.enrich(
        [
            first,
            second,
        ],
    )

    assert first.identifier == "CVE-2025-0001"
    assert second.identifier == "CVE-2025-0002"
