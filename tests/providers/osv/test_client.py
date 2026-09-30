import json

import httpx

from sentinel.enums.ecosystem import Ecosystem
from sentinel.providers.osv.client import OSVClient
from sentinel.providers.osv.models import OSVResponse


def test_query_returns_osv_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"

        payload = json.loads(request.content)

        assert payload == {
            "package": {
                "name": "requests",
                "ecosystem": "PyPI",
            },
            "version": "2.31.0",
        }

        return httpx.Response(
            200,
            json={
                "vulns": [
                    {
                        "id": "CVE-1",
                    }
                ]
            },
        )

    transport = httpx.MockTransport(handler)

    client = OSVClient(
        httpx.Client(
            transport=transport,
        )
    )
    result = client.query(
        package_name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
    )

    assert isinstance(result, OSVResponse)
    assert len(result.vulns) == 1

    vuln = result.vulns[0]

    assert vuln.identifier == "CVE-1"
    assert vuln.summary == ""
    assert vuln.severity == []
    assert vuln.cvss is None


def test_query_raises_for_http_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    transport = httpx.MockTransport(handler)

    client = OSVClient(
        httpx.Client(
            transport=transport,
        )
    )

    try:
        client.query(
            package_name="requests",
            version="2.31.0",
            ecosystem=Ecosystem.PYPI,
        )
        raise ValueError("Expected HTTPStatusError")
    except httpx.HTTPStatusError:
        pass


def test_close() -> None:
    http_client = httpx.Client()

    client = OSVClient(http_client)

    client.close()

    assert http_client.is_closed


def test_parse_response_extracts_fixed_versions() -> None:
    client = OSVClient()

    payload = {
        "vulns": [
            {
                "id": "GHSA-test-fixed",
                "aliases": [
                    "CVE-2026-0001",
                ],
                "summary": "Test vulnerability",
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "7.5",
                    }
                ],
                "affected": [
                    {
                        "package": {
                            "name": "requests",
                            "ecosystem": "PyPI",
                        },
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {
                                        "introduced": "0",
                                    },
                                    {
                                        "fixed": "2.32.4",
                                    },
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }

    result = client._parse_response(
        payload,
    )

    assert isinstance(
        result,
        OSVResponse,
    )

    assert len(result.vulns) == 1

    vulnerability = result.vulns[0]

    assert vulnerability.identifier == "GHSA-test-fixed"

    assert vulnerability.fixed_versions == [
        "2.32.4",
    ]

    assert len(vulnerability.affected) == 1

    assert vulnerability.affected[0].ranges[0].events[1].fixed == ("2.32.4")


def test_parse_response_extracts_multiple_fixed_versions() -> None:
    client = OSVClient()

    payload = {
        "vulns": [
            {
                "id": "GHSA-multiple-fixed",
                "aliases": [],
                "summary": "Multiple fixed versions",
                "severity": [],
                "affected": [
                    {
                        "package": {
                            "name": "django",
                        },
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {
                                        "introduced": "0",
                                    },
                                    {
                                        "fixed": "7.15.2",
                                    },
                                    {
                                        "fixed": "8.0.1",
                                    },
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }

    result = client._parse_response(
        payload,
    )

    vulnerability = result.vulns[0]

    assert vulnerability.fixed_versions == [
        "7.15.2",
        "8.0.1",
    ]


def test_parse_response_without_fixed_version_returns_empty_list() -> None:
    client = OSVClient()

    payload = {
        "vulns": [
            {
                "id": "GHSA-no-fixed",
                "aliases": [],
                "summary": "No fix available",
                "severity": [],
                "affected": [
                    {
                        "package": {
                            "name": "package",
                        },
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {
                                        "introduced": "0",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }

    result = client._parse_response(
        payload,
    )

    vulnerability = result.vulns[0]

    assert vulnerability.fixed_versions == []
