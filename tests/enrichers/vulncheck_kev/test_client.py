import io
import json
import zipfile
from datetime import datetime
from unittest.mock import Mock

import httpx
import pytest

from sentinel.enrichers.vulncheck_kev.client import VulnCheckKEVClient
from sentinel.exceptions.enricher import VulnCheckKEVRequestError
from sentinel.exceptions.enricher import VulnCheckKEVResponseError


def make_backup(
    data: dict[str, object],
) -> bytes:
    buffer = io.BytesIO()

    with zipfile.ZipFile(
        buffer,
        "w",
        zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "vulncheck_known_exploited_vulnerabilities.json",
            json.dumps(data),
        )

    return buffer.getvalue()


def make_client(
    response: httpx.Response | None = None,
    exception: Exception | None = None,
) -> VulnCheckKEVClient:
    calls = 0

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        nonlocal calls

        if exception is not None:
            raise exception

        assert request.method == "GET"

        if calls == 0:
            calls += 1

            assert request.headers["Authorization"].startswith(
                "Bearer ",
            )
            assert request.headers["Accept"] == "application/json"

            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "filename": "vulncheck-kev.zip",
                            "url": "https://backup.test/vulncheck-kev.zip",
                        },
                    ],
                },
            )

        calls += 1

        if response is None:
            return httpx.Response(
                200,
                content=make_backup(
                    {
                        "data": [],
                    },
                ),
            )

        return response

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
    )

    return VulnCheckKEVClient(
        client=client,
    )


def test_load_returns_empty_catalog() -> None:
    client = make_client()

    catalog = client.load()

    assert catalog == {}

    client.close()


def test_load_parses_vulnerability() -> None:
    response = httpx.Response(
        200,
        content=make_backup(
            {
                "data": [
                    {
                        "cve": ["CVE-2025-0001"],
                        "vendorProject": "Example Vendor",
                        "product": "Example Product",
                        "shortDescription": "Example vulnerability",
                        "vulnerabilityName": "Example Vulnerability",
                        "required_action": "Apply the vendor patch.",
                        "knownRansomwareCampaignUse": "Known",
                        "reported_exploited_by_vulncheck_canaries": True,
                        "date_added": "2025-01-10T12:30:00Z",
                        "cisa_date_added": "2025-01-11T08:15:00Z",
                        "dueDate": "2025-02-10T00:00:00Z",
                    },
                ],
            },
        ),
    )

    client = make_client(response)

    catalog = client.load()

    vulnerability = catalog["CVE-2025-0001"]

    assert vulnerability.cve_ids == [
        "CVE-2025-0001",
    ]
    assert vulnerability.vendor == "Example Vendor"
    assert vulnerability.product == "Example Product"
    assert vulnerability.short_description == ("Example vulnerability")
    assert vulnerability.vulnerability_name == ("Example Vulnerability")
    assert vulnerability.required_action == ("Apply the vendor patch.")
    assert vulnerability.known_ransomware == "Known"
    assert vulnerability.reported_exploited_by_canaries is True

    assert vulnerability.date_added == datetime.fromisoformat(
        "2025-01-10T12:30:00+00:00",
    )
    assert vulnerability.cisa_date_added == datetime.fromisoformat(
        "2025-01-11T08:15:00+00:00",
    )
    assert vulnerability.due_date == datetime.fromisoformat(
        "2025-02-10T00:00:00+00:00",
    )

    client.close()


def test_load_indexes_multiple_cves() -> None:
    response = httpx.Response(
        200,
        content=make_backup(
            {
                "data": [
                    {
                        "cve": [
                            "CVE-2025-0001",
                            "CVE-2025-0002",
                        ],
                        "vendorProject": "Example Vendor",
                        "product": "Example Product",
                        "shortDescription": "Example vulnerability",
                        "vulnerabilityName": "Example Vulnerability",
                        "required_action": "Apply the vendor patch.",
                        "knownRansomwareCampaignUse": "Known",
                        "reported_exploited_by_vulncheck_canaries": False,
                    },
                ],
            },
        ),
    )

    client = make_client(response)

    catalog = client.load()

    assert "CVE-2025-0001" in catalog
    assert "CVE-2025-0002" in catalog
    assert catalog["CVE-2025-0001"] is catalog["CVE-2025-0002"]

    client.close()


def test_load_ignores_invalid_cve_entries() -> None:
    response = httpx.Response(
        200,
        content=make_backup(
            {
                "data": [
                    {
                        "cve": [
                            "CVE-2025-0001",
                            123,
                            None,
                        ],
                        "vendorProject": "Example Vendor",
                        "product": "Example Product",
                        "shortDescription": "Example vulnerability",
                        "vulnerabilityName": "Example Vulnerability",
                        "required_action": "Apply the vendor patch.",
                        "knownRansomwareCampaignUse": "Unknown",
                        "reported_exploited_by_vulncheck_canaries": False,
                    },
                ],
            },
        ),
    )

    client = make_client(response)

    catalog = client.load()

    assert list(catalog) == ["CVE-2025-0001"]

    client.close()


def test_load_handles_invalid_dates() -> None:
    response = httpx.Response(
        200,
        content=make_backup(
            {
                "data": [
                    {
                        "cve": ["CVE-2025-0001"],
                        "vendorProject": "Example Vendor",
                        "product": "Example Product",
                        "shortDescription": "Example vulnerability",
                        "vulnerabilityName": "Example Vulnerability",
                        "required_action": "Apply the vendor patch.",
                        "knownRansomwareCampaignUse": "Unknown",
                        "reported_exploited_by_vulncheck_canaries": False,
                        "date_added": "invalid",
                        "cisa_date_added": None,
                        "dueDate": 123,
                    },
                ],
            },
        ),
    )

    client = make_client(response)

    catalog = client.load()

    vulnerability = catalog["CVE-2025-0001"]

    assert vulnerability.date_added is None
    assert vulnerability.cisa_date_added is None
    assert vulnerability.due_date is None

    client.close()


def make_invalid_json_backup() -> bytes:
    buffer = io.BytesIO()

    with zipfile.ZipFile(
        buffer,
        "w",
        zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "vulncheck_known_exploited_vulnerabilities.json",
            b"not-json",
        )

    return buffer.getvalue()


def test_load_handles_http_error() -> None:
    response = httpx.Response(
        401,
        content=make_backup(
            {
                "error": "Unauthorized",
            },
        ),
    )

    client = make_client(response)

    with pytest.raises(VulnCheckKEVResponseError):
        client.load()

    client.close()


def test_load_handles_request_error() -> None:
    client = make_client(
        exception=httpx.ConnectError(
            "Connection failed",
        ),
    )

    with pytest.raises(VulnCheckKEVRequestError):
        client.load()

    client.close()


def test_load_handles_non_dict_items() -> None:
    response = httpx.Response(
        200,
        content=make_backup(
            {
                "data": [
                    "invalid",
                    None,
                    123,
                    {
                        "cve": ["CVE-2025-0001"],
                        "vendorProject": "Example Vendor",
                        "product": "Example Product",
                        "shortDescription": "Example vulnerability",
                        "vulnerabilityName": "Example Vulnerability",
                        "required_action": "Apply the vendor patch.",
                        "knownRansomwareCampaignUse": "Unknown",
                        "reported_exploited_by_vulncheck_canaries": False,
                    },
                ],
            }
        ),
    )

    client = make_client(response)

    catalog = client.load()

    assert list(catalog) == ["CVE-2025-0001"]

    client.close()


def test_client_uses_configured_token() -> None:
    client = Mock()

    vulncheck_client = VulnCheckKEVClient(
        client=client,
    )

    assert vulncheck_client.api_token is not None

    vulncheck_client.close()
