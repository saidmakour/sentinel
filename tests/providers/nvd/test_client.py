from unittest.mock import Mock

import httpx
import pytest

from sentinel.providers.nvd.client import NVDClient
from sentinel.providers.nvd.exceptions import NVDRequestError
from sentinel.providers.nvd.exceptions import NVDResponseError


@pytest.fixture
def http_client() -> Mock:
    return Mock(spec=httpx.Client)


@pytest.fixture
def client(http_client: Mock) -> NVDClient:
    return NVDClient(client=http_client)


def test_headers_without_api_key(client: NVDClient) -> None:
    client.api_key = ""

    assert client._headers() == {
        "User-Agent": "Sentinel",
    }


def test_headers_with_api_key(client: NVDClient) -> None:
    client.api_key = "abc123"

    assert client._headers() == {
        "User-Agent": "Sentinel",
        "apiKey": "abc123",
    }


def test_extract_summary_returns_english(client: NVDClient) -> None:
    descriptions = [
        {
            "lang": "fr",
            "value": "Résumé",
        },
        {
            "lang": "en",
            "value": "English summary",
        },
    ]

    assert client._extract_summary(descriptions) == "English summary"


def test_extract_summary_returns_empty(client: NVDClient) -> None:
    descriptions = [
        {
            "lang": "fr",
            "value": "Résumé",
        }
    ]

    assert client._extract_summary(descriptions) == ""


def test_extract_cvss_v40(client: NVDClient) -> None:
    cve = {
        "metrics": {
            "cvssMetricV40": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                    }
                }
            ]
        }
    }

    assert client._extract_cvss_score(cve) == 9.8


def test_extract_cvss_v31(client: NVDClient) -> None:
    cve = {
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 8.2,
                    }
                }
            ]
        }
    }

    assert client._extract_cvss_score(cve) == 8.2


def test_extract_cvss_v30(client: NVDClient) -> None:
    cve = {
        "metrics": {
            "cvssMetricV30": [
                {
                    "cvssData": {
                        "baseScore": 7.4,
                    }
                }
            ]
        }
    }

    assert client._extract_cvss_score(cve) == 7.4


def test_extract_cvss_v2(client: NVDClient) -> None:
    cve = {
        "metrics": {
            "cvssMetricV2": [
                {
                    "cvssData": {
                        "baseScore": 5.0,
                    }
                }
            ]
        }
    }

    assert client._extract_cvss_score(cve) == 5.0


def test_extract_cvss_returns_none(client: NVDClient) -> None:
    assert client._extract_cvss_score({}) is None


def test_parse_vulnerability(client: NVDClient) -> None:
    vulnerability = client._parse_vulnerability(
        {
            "cve": {
                "id": "CVE-2025-1234",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Example vulnerability",
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.1,
                            }
                        }
                    ]
                },
            }
        }
    )

    assert vulnerability.identifier == "CVE-2025-1234"
    assert vulnerability.summary == "Example vulnerability"
    assert vulnerability.metric.score == 9.1


def test_parse(client: NVDClient) -> None:
    response = client._parse(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-1",
                        "descriptions": [],
                        "metrics": {},
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2",
                        "descriptions": [],
                        "metrics": {},
                    }
                },
            ]
        }
    )

    assert len(response.vulnerabilities) == 2
    assert response.vulnerabilities[0].identifier == "CVE-1"
    assert response.vulnerabilities[1].identifier == "CVE-2"


def test_query_returns_response(
    client: NVDClient,
    http_client: Mock,
) -> None:
    response = Mock()

    response.raise_for_status.return_value = None

    response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2025-1234",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Example",
                        }
                    ],
                    "metrics": {},
                }
            }
        ]
    }

    http_client.get.return_value = response

    result = client.query("requests")

    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].identifier == "CVE-2025-1234"

    http_client.get.assert_called_once()


def test_query_http_error(
    client: NVDClient,
    http_client: Mock,
) -> None:
    response = Mock()

    response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "boom",
        request=Mock(),
        response=Mock(),
    )

    http_client.get.return_value = response

    with pytest.raises(NVDResponseError):
        client.query("requests")


def test_query_request_error(
    client: NVDClient,
    http_client: Mock,
) -> None:
    http_client.get.side_effect = httpx.RequestError(
        "boom",
        request=Mock(),
    )

    with pytest.raises(NVDRequestError):
        client.query("requests")


def test_query_invalid_json(
    client: NVDClient,
    http_client: Mock,
) -> None:
    response = Mock()

    response.raise_for_status.return_value = None

    response.json.side_effect = ValueError()

    http_client.get.return_value = response

    with pytest.raises(NVDResponseError):
        client.query("requests")


def test_parse_empty_response(client: NVDClient) -> None:
    response = client._parse({})

    assert response.vulnerabilities == []


def test_extract_summary_empty_list(client: NVDClient) -> None:
    assert client._extract_summary([]) == ""


def test_extract_cvss_invalid_score(client: NVDClient) -> None:
    cve = {
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": "N/A",
                    }
                }
            ]
        }
    }

    assert client._extract_cvss_score(cve) is None
