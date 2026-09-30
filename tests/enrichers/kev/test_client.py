from datetime import date

import httpx
import pytest

from sentinel.enrichers.kev.client import KEVClient
from sentinel.enrichers.kev.models import KEVVulnerability
from sentinel.exceptions.enricher import KEVRequestError
from sentinel.exceptions.enricher import KEVResponseError


def test_load_returns_catalog() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"

        return httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2025-0001",
                        "dateAdded": "2025-01-15",
                        "dueDate": "2025-02-05",
                        "vendorProject": "Apache",
                        "product": "Tomcat",
                        "requiredAction": "Update",
                        "knownRansomwareCampaignUse": "Known",
                    }
                ]
            },
        )

    transport = httpx.MockTransport(handler)

    client = KEVClient(
        httpx.Client(
            transport=transport,
        )
    )

    catalog = client.load()

    assert len(catalog) == 1

    kev = catalog["CVE-2025-0001"]

    assert isinstance(kev, KEVVulnerability)

    assert kev.cve_id == "CVE-2025-0001"
    assert kev.vendor == "Apache"
    assert kev.product == "Tomcat"
    assert kev.required_action == "Update"
    assert kev.known_ransomware == "Known"

    assert kev.date_added == date(
        2025,
        1,
        15,
    )

    assert kev.due_date == date(
        2025,
        2,
        5,
    )


def test_load_returns_empty_catalog() -> None:
    transport = httpx.MockTransport(
        lambda _: httpx.Response(
            200,
            json={
                "vulnerabilities": [],
            },
        )
    )

    client = KEVClient(
        httpx.Client(
            transport=transport,
        )
    )

    catalog = client.load()

    assert catalog == {}


def test_load_raises_response_error_on_http_error() -> None:
    transport = httpx.MockTransport(
        lambda _: httpx.Response(
            500,
        )
    )

    client = KEVClient(
        httpx.Client(
            transport=transport,
        )
    )

    with pytest.raises(
        KEVResponseError,
    ):
        client.load()


def test_load_raises_response_error_on_invalid_json() -> None:
    transport = httpx.MockTransport(
        lambda _: httpx.Response(
            200,
            text="invalid json",
        )
    )

    client = KEVClient(
        httpx.Client(
            transport=transport,
        )
    )

    with pytest.raises(
        KEVResponseError,
    ):
        client.load()


def test_load_raises_request_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "Connection failed",
        )

    transport = httpx.MockTransport(handler)

    client = KEVClient(
        httpx.Client(
            transport=transport,
        )
    )

    with pytest.raises(
        KEVRequestError,
    ):
        client.load()


def test_close() -> None:
    http_client = httpx.Client()

    client = KEVClient(http_client)

    client.close()

    assert http_client.is_closed
