import httpx

from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enrichers.epss.client import EPSSClient
from sentinel.enrichers.epss.enricher import EPSSEnricher
from sentinel.enrichers.epss.models import EPSSScore
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity


def test_load_returns_catalog() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"

        assert request.url.params["cve"] == ("CVE-2025-0001,CVE-2025-0002")

        return httpx.Response(
            200,
            json={
                "status": "OK",
                "data": [
                    {
                        "cve": "CVE-2025-0001",
                        "epss": "0.98",
                        "percentile": "0.99",
                    },
                    {
                        "cve": "CVE-2025-0002",
                        "epss": "0.12",
                        "percentile": "0.60",
                    },
                ],
            },
        )

    transport = httpx.MockTransport(handler)

    client = EPSSClient(
        httpx.Client(
            transport=transport,
        )
    )

    result = client.load(
        [
            "CVE-2025-0001",
            "CVE-2025-0002",
        ]
    )

    assert len(result) == 2

    assert result["CVE-2025-0001"].score == 0.98
    assert result["CVE-2025-0001"].percentile == 0.99

    assert result["CVE-2025-0002"].score == 0.12
    assert result["CVE-2025-0002"].percentile == 0.60


def test_load_returns_empty_catalog_when_no_identifier() -> None:
    client = EPSSClient()

    result = client.load([])

    assert result == {}


def test_load_raises_http_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    transport = httpx.MockTransport(handler)

    client = EPSSClient(
        httpx.Client(
            transport=transport,
        )
    )

    try:
        client.load(
            ["CVE-2025-0001"],
        )

        raise ValueError(
            "Expected HTTPStatusError",
        )

    except httpx.HTTPStatusError:
        pass


def test_close() -> None:
    http_client = httpx.Client()

    client = EPSSClient(
        http_client,
    )

    client.close()

    assert http_client.is_closed


class FakeEPSSClient:
    def __init__(self) -> None:
        self.called = False
        self.identifiers: list[str] | None = None

    def load(
        self,
        identifiers: list[str],
    ) -> dict[str, EPSSScore]:
        self.called = True
        self.identifiers = identifiers

        return {
            "CVE-2025-0001": EPSSScore(
                cve="CVE-2025-0001",
                score=0.97321,
                percentile=0.99871,
            )
        }


def test_enrich_updates_findings() -> None:
    client = FakeEPSSClient()

    enricher = EPSSEnricher(
        client=client,
    )

    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2025-0001",
        aliases=["CVE-2025-0001"],
        sources=[Provider.OSV],
        severity=Severity.HIGH,
        cvss=9.8,
        summary="Example vulnerability",
    )

    enricher.enrich(
        [finding],
    )

    assert finding.epss_score == 0.97321
    assert finding.epss_percentile == 0.99871


def test_enrich_ignores_unknown_cve() -> None:
    client = FakeEPSSClient()

    enricher = EPSSEnricher(
        client=client,
    )

    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2099-9999",
        aliases=["CVE-2099-9999"],
        sources=[Provider.OSV],
        severity=Severity.HIGH,
        cvss=9.8,
        summary="Unknown CVE",
    )

    enricher.enrich(
        [finding],
    )

    assert finding.epss_score is None
    assert finding.epss_percentile is None


def test_enrich_with_empty_findings() -> None:
    client = FakeEPSSClient()

    enricher = EPSSEnricher(
        client=client,
    )

    enricher.enrich([])

    assert client.called is False


def test_enrich_calls_client_once() -> None:
    client = FakeEPSSClient()

    enricher = EPSSEnricher(
        client=client,
    )

    findings = [
        VulnerabilityInfo(
            dependency_name="requests",
            dependency_version="2.31.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-2025-0001",
            aliases=["CVE-2025-0001"],
            sources=[Provider.OSV],
            severity=Severity.HIGH,
            cvss=9.8,
            summary="Example 1",
        ),
        VulnerabilityInfo(
            dependency_name="urllib3",
            dependency_version="2.2.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-2025-0002",
            aliases=["CVE-2025-0002"],
            sources=[Provider.OSV],
            severity=Severity.MEDIUM,
            cvss=6.5,
            summary="Example 2",
        ),
    ]

    enricher.enrich(
        findings,
    )

    assert client.called

    assert client.identifiers is not None
    assert set(client.identifiers) == {
        "CVE-2025-0001",
        "CVE-2025-0002",
    }


def test_enrich_deduplicates_identifiers() -> None:
    client = FakeEPSSClient()

    enricher = EPSSEnricher(
        client=client,
    )

    findings = [
        VulnerabilityInfo(
            dependency_name="requests",
            dependency_version="2.31.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-2025-0001",
            aliases=["CVE-2025-0001"],
            sources=[Provider.OSV],
            severity=Severity.HIGH,
            cvss=9.8,
            summary="Example 1",
        ),
        VulnerabilityInfo(
            dependency_name="urllib3",
            dependency_version="2.2.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-2025-0001",
            aliases=["CVE-2025-0001"],
            sources=[Provider.OSV],
            severity=Severity.HIGH,
            cvss=9.8,
            summary="Example 2",
        ),
    ]

    enricher.enrich(findings)

    assert client.identifiers is not None
    assert len(client.identifiers) == 1
    assert client.identifiers[0] == "CVE-2025-0001"
