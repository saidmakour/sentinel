from unittest.mock import patch

import httpx
import pytest

from sentinel.providers.nvd.client import NVDClient
from sentinel.providers.nvd.exceptions import NVDResponseError


def make_response(
    status_code: int,
    headers: dict[str, str] | None = None,
    json_data: dict | None = None,
) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        headers=headers or {},
        json=json_data,
        request=httpx.Request(
            "GET",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
        ),
    )


def test_query_raises_after_max_retries() -> None:
    client = NVDClient(
        client=httpx.Client(),
    )

    responses = [
        make_response(429),
        make_response(429),
        make_response(429),
        make_response(429),
    ]

    with (
        patch.object(
            client.client,
            "get",
            side_effect=responses,
        ) as mock_get,
        patch(
            "sentinel.providers.nvd.client.time.sleep",
        ),
    ):
        with pytest.raises(
            NVDResponseError,
            match="NVD rate limit exceeded",
        ):
            client.query(
                "django",
            )

    assert mock_get.call_count == (client.max_retries + 1)


def test_query_uses_retry_after_header() -> None:
    client = NVDClient(
        client=httpx.Client(),
    )

    responses = [
        make_response(
            429,
            headers={
                "Retry-After": "5",
            },
        ),
        make_response(
            200,
            json_data={
                "vulnerabilities": [],
            },
        ),
    ]

    with (
        patch.object(
            client.client,
            "get",
            side_effect=responses,
        ) as mock_get,
        patch(
            "sentinel.providers.nvd.client.time.sleep",
        ) as mock_sleep,
    ):
        response = client.query(
            "django",
        )

    assert response is not None

    assert mock_get.call_count == 2

    assert mock_sleep.call_count == 2

    assert any(call.args == (5,) for call in mock_sleep.call_args_list)


def test_query_uses_exponential_backoff_when_retry_after_is_missing() -> None:
    client = NVDClient(
        client=httpx.Client(),
    )

    responses = [
        make_response(
            429,
        ),
        make_response(
            200,
            json_data={
                "vulnerabilities": [],
            },
        ),
    ]

    with (
        patch.object(
            client.client,
            "get",
            side_effect=responses,
        ) as mock_get,
        patch(
            "sentinel.providers.nvd.client.time.sleep",
        ) as mock_sleep,
    ):
        response = client.query(
            "django",
        )

    assert response is not None

    assert mock_get.call_count == 2

    assert mock_sleep.call_count == 2

    assert any(
        call.args == (client.retry_backoff,)
        for call in mock_sleep.call_args_list
    )


def test_query_ignores_invalid_retry_after_header() -> None:
    client = NVDClient(
        client=httpx.Client(),
    )

    responses = [
        make_response(
            429,
            headers={
                "Retry-After": "invalid",
            },
        ),
        make_response(
            200,
            json_data={
                "vulnerabilities": [],
            },
        ),
    ]

    with (
        patch.object(
            client.client,
            "get",
            side_effect=responses,
        ) as mock_get,
        patch(
            "sentinel.providers.nvd.client.time.sleep",
        ) as mock_sleep,
    ):
        response = client.query(
            "django",
        )

    assert response is not None

    assert mock_get.call_count == 2

    assert mock_sleep.call_count == 2

    assert any(
        call.args == (client.retry_backoff,)
        for call in mock_sleep.call_args_list
    )


def test_parse_extracts_cpe_fixed_version():

    client = NVDClient(
        client=httpx.Client(),
    )

    response = client._parse(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-48998",
                        "references": [],
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "test",
                            }
                        ],
                        "metrics": {},
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "criteria": "cpe:2.3:a:django:django:*",
                                                "versionEndExcluding": "2.10.2",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
            ]
        }
    )

    vuln = response.vulnerabilities[0]
    print(vuln)
    assert len(vuln.configurations) == 1

    assert vuln.configurations[0].version_end_excluding == "2.10.2"
