from unittest.mock import MagicMock

import httpx
import pytest

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.ecosystem import Ecosystem
from sentinel.providers.ghsa.client import GHSAClient
from sentinel.providers.ghsa.exceptions import GHSARequestError
from sentinel.providers.ghsa.mapper import GHSAMapper
from sentinel.providers.ghsa.models import GHSACVSS
from sentinel.providers.ghsa.models import GHSAResponse
from sentinel.providers.ghsa.models import GHSAVulnerability


def test_ghsa_client_can_be_created() -> None:
    client = GHSAClient()

    assert client is not None


def test_headers_without_token(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "sentinel.providers.ghsa.client.settings.ghsa_token",
        "",
    )

    client = GHSAClient()

    headers = client._headers()

    assert headers == {
        "User-Agent": "Sentinel",
        "Content-Type": "application/json",
    }


def test_headers_with_token(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "sentinel.providers.ghsa.client.settings.ghsa_token",
        "secret-token",
    )

    client = GHSAClient()

    headers = client._headers()

    assert headers["Authorization"] == "Bearer secret-token"


def test_query_returns_response() -> None:
    response = MagicMock()

    response.json.return_value = []

    response.raise_for_status.return_value = None

    http_client = MagicMock()

    http_client.get.return_value = response

    client = GHSAClient(
        client=http_client,
    )

    result = client.query(
        package_name="requests",
        ecosystem="pip",
    )

    assert isinstance(
        result,
        GHSAResponse,
    )

    http_client.get.assert_called_once()


def test_query_raises_request_error_on_http_status() -> None:
    response = httpx.Response(
        status_code=500,
        request=httpx.Request(
            "GET",
            "https://api.github.com",
        ),
    )

    http_client = MagicMock()
    http_client.get.return_value = response

    client = GHSAClient(
        client=http_client,
    )

    with pytest.raises(
        GHSARequestError,
    ):
        client.query(
            package_name="requests",
            ecosystem="pip",
        )


def test_query_raises_request_error_on_invalid_json() -> None:
    response = MagicMock()

    response.raise_for_status.return_value = None
    response.json.side_effect = ValueError(
        "invalid json",
    )

    http_client = MagicMock()
    http_client.get.return_value = response

    client = GHSAClient(
        client=http_client,
    )

    with pytest.raises(
        GHSARequestError,
    ):
        client.query(
            package_name="requests",
            ecosystem="pip",
        )


def test_query_raises_request_error() -> None:
    response = MagicMock()

    response.raise_for_status.side_effect = httpx.RequestError(
        "network error",
    )

    http_client = MagicMock()

    http_client.get.return_value = response

    client = GHSAClient(
        client=http_client,
    )

    with pytest.raises(
        GHSARequestError,
    ):
        client.query(
            package_name="requests",
            ecosystem="pip",
        )


def test_parse_empty_response() -> None:
    client = GHSAClient()

    result = client._parse_response(
        [],
    )

    assert result.vulnerabilities == []


def test_parse_single_vulnerability() -> None:
    client = GHSAClient()

    result = client._parse_response(
        [
            {
                "ghsa_id": "GHSA-1234",
                "cve_id": "CVE-2026-0001",
                "summary": "Example",
                "severity": "HIGH",
                "identifiers": [],
            },
        ],
    )

    assert len(result.vulnerabilities) == 1

    vulnerability = result.vulnerabilities[0]

    assert vulnerability.ghsa_id == "GHSA-1234"
    assert vulnerability.cve_id == "CVE-2026-0001"
    assert vulnerability.summary == "Example"
    assert vulnerability.severity == "HIGH"


def test_parse_multiple_vulnerabilities() -> None:
    client = GHSAClient()

    result = client._parse_response(
        [
            {
                "ghsa_id": "GHSA-1",
                "summary": "One",
                "severity": "LOW",
            },
            {
                "ghsa_id": "GHSA-2",
                "summary": "Two",
                "severity": "HIGH",
            },
        ],
    )

    assert len(result.vulnerabilities) == 2


def test_parse_package() -> None:
    client = GHSAClient()

    result = client._parse_response(
        [
            {
                "ghsa_id": "GHSA-123",
                "summary": "Example",
                "severity": "HIGH",
                "vulnerabilities": [
                    {
                        "package": {
                            "ecosystem": "pip",
                            "name": "requests",
                        },
                    },
                ],
            },
        ],
    )

    package = result.vulnerabilities[0].package

    assert package is not None
    assert package.ecosystem == "pip"
    assert package.name == "requests"


def create_dependency() -> ScannedDependency:
    return ScannedDependency(
        name="requests",
        version="2.32.0",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
    )


def test_map_cvss_score() -> None:
    mapper = GHSAMapper()

    response = GHSAResponse(
        vulnerabilities=[
            GHSAVulnerability(
                ghsa_id="GHSA-3333",
                cve_id=None,
                summary="Example",
                description="",
                severity="CRITICAL",
                identifiers=[],
                cvss_v3=GHSACVSS(
                    score=9.8,
                    vector_string="CVSS:3.1/...",
                ),
            )
        ]
    )

    findings = mapper.map(
        create_dependency(),
        response,
    )

    assert findings[0].cvss == 9.8


def test_map_prefers_cvss_v4() -> None:
    mapper = GHSAMapper()

    response = GHSAResponse(
        vulnerabilities=[
            GHSAVulnerability(
                ghsa_id="GHSA-3333",
                cve_id=None,
                summary="Example",
                description="",
                severity="CRITICAL",
                identifiers=[],
                cvss_v3=GHSACVSS(score=7.5),
                cvss_v4=GHSACVSS(score=9.3),
            )
        ]
    )

    findings = mapper.map(
        create_dependency(),
        response,
    )

    assert findings[0].cvss == 9.3
