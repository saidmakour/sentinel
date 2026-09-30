from datetime import date

from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enrichers.kev.enricher import KEVEnricher
from sentinel.enrichers.kev.models import KEVVulnerability
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider


class FakeClient:
    def __init__(self) -> None:
        self.called = False

    def load(
        self,
    ) -> dict[str, KEVVulnerability]:
        self.called = True

        return {
            "CVE-2025-0001": KEVVulnerability(
                cve_id="CVE-2025-0001",
                date_added=date(
                    2025,
                    1,
                    15,
                ),
                due_date=date(
                    2025,
                    2,
                    1,
                ),
                vendor="Apache",
                product="Tomcat",
                required_action="Update immediately",
                known_ransomware="Known",
            ),
        }


def make_finding(
    identifier: str,
) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        identifier=identifier,
        aliases=[identifier],
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        sources=[Provider.OSV],
        severity="HIGH",
        cvss=9.8,
        summary="Example vulnerability",
    )


def test_enrich_marks_known_exploited() -> None:
    client = FakeClient()

    enricher = KEVEnricher(
        client=client,
    )

    findings = [
        make_finding(
            "CVE-2025-0001",
        )
    ]

    enricher.enrich(
        findings,
    )

    assert client.called

    finding = findings[0]

    assert finding.known_exploited is True
    assert finding.kev_date_added == date(
        2025,
        1,
        15,
    )
    assert finding.kev_vendor == "Apache"
    assert finding.kev_product == "Tomcat"
    assert finding.kev_required_action == "Update immediately"
    assert finding.kev_known_ransomware == "Known"


def test_enrich_ignores_unknown_cve() -> None:
    client = FakeClient()

    enricher = KEVEnricher(
        client=client,
    )

    findings = [
        make_finding(
            "CVE-2099-9999",
        )
    ]

    enricher.enrich(
        findings,
    )

    finding = findings[0]

    assert finding.known_exploited is False
    assert finding.kev_date_added is None
    assert finding.kev_vendor is None
    assert finding.kev_product is None
    assert finding.kev_required_action is None
    assert finding.kev_known_ransomware is None


def test_enrich_multiple_findings() -> None:
    client = FakeClient()

    enricher = KEVEnricher(
        client=client,
    )

    findings = [
        make_finding(
            "CVE-2025-0001",
        ),
        make_finding(
            "CVE-2099-9999",
        ),
    ]

    enricher.enrich(
        findings,
    )

    assert findings[0].known_exploited is True
    assert findings[1].known_exploited is False


def test_enrich_empty_findings() -> None:
    client = FakeClient()

    enricher = KEVEnricher(
        client=client,
    )

    findings: list[VulnerabilityInfo] = []

    enricher.enrich(
        findings,
    )

    assert client.called
    assert findings == []
