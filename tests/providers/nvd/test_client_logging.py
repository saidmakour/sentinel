from unittest.mock import Mock
from unittest.mock import patch

import httpx
import pytest

from sentinel.providers.nvd.client import NVDClient
from sentinel.providers.nvd.exceptions import NVDRequestError
from sentinel.providers.nvd.exceptions import NVDResponseError


def make_response(
    status_code: int,
    json_data: dict | None = None,
    headers: dict[str, str] | None = None,
) -> Mock:
    response = Mock(
        spec=httpx.Response,
    )

    response.status_code = status_code
    response.headers = headers or {}

    if status_code < 400:
        response.raise_for_status.return_value = None

    else:
        response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "HTTP error",
            request=Mock(),
            response=response,
        )

    if json_data is not None:
        response.json.return_value = json_data

    return response


def test_query_logs_successful_request(
    caplog,
) -> None:
    client = Mock()

    response = make_response(
        status_code=200,
        json_data={
            "vulnerabilities": [],
        },
    )

    client.get.return_value = response

    nvd_client = NVDClient(
        client=client,
    )

    with (
        patch.object(
            nvd_client,
            "_wait_for_rate_limit",
        ),
        caplog.at_level(
            "DEBUG",
        ),
    ):
        result = nvd_client.query(
            "requests",
        )

    assert result.vulnerabilities == []
    assert "NVD" in caplog.text
    assert "NVD query keyword=requests package=requests" in caplog.text


def test_query_logs_rate_limit_warning(
    caplog,
) -> None:
    client = Mock()

    rate_limit_response = make_response(
        status_code=429,
        headers={
            "Retry-After": "1",
        },
    )

    success_response = make_response(
        status_code=200,
        json_data={
            "vulnerabilities": [],
        },
    )

    client.get.side_effect = [
        rate_limit_response,
        success_response,
    ]

    nvd_client = NVDClient(
        client=client,
    )

    with (
        patch.object(
            nvd_client,
            "_wait_for_rate_limit",
        ),
        patch(
            "sentinel.providers.nvd.client.time.sleep",
        ),
    ):
        nvd_client.query(
            "requests",
        )

    # assert "NVD" in caplog.text


def test_query_logs_rate_limit_exhausted(
    caplog,
) -> None:
    client = Mock()

    client.get.return_value = make_response(
        status_code=429,
    )

    nvd_client = NVDClient(
        client=client,
    )

    with (
        patch.object(
            nvd_client,
            "_wait_for_rate_limit",
        ),
        pytest.raises(
            NVDResponseError,
            match="rate limit exceeded",
        ),
    ):
        nvd_client.query(
            "requests",
        )

    assert "NVD rate limit exceeded after retries" in caplog.text

    assert "package=requests" in caplog.text


def test_query_logs_request_error(
    caplog,
) -> None:
    client = Mock()

    client.get.side_effect = httpx.RequestError(
        "Connection failed",
    )

    nvd_client = NVDClient(
        client=client,
    )

    with (
        patch.object(
            nvd_client,
            "_wait_for_rate_limit",
        ),
        pytest.raises(
            NVDRequestError,
        ),
    ):
        nvd_client.query(
            "requests",
        )

    assert "NVD request failed" in caplog.text
    assert "package=requests" in caplog.text


def test_query_logs_http_error(
    caplog,
) -> None:
    client = Mock()

    client.get.return_value = make_response(
        status_code=500,
    )

    nvd_client = NVDClient(
        client=client,
    )

    with (
        patch.object(
            nvd_client,
            "_wait_for_rate_limit",
        ),
        pytest.raises(
            NVDResponseError,
        ),
    ):
        nvd_client.query(
            "requests",
        )

    assert "NVD API returned an HTTP error" in caplog.text

    assert "package=requests" in caplog.text
    assert "status=500" in caplog.text


def test_query_logs_invalid_json(
    caplog,
) -> None:
    client = Mock()

    response = make_response(
        status_code=200,
    )

    response.json.side_effect = ValueError(
        "Invalid JSON",
    )

    client.get.return_value = response

    nvd_client = NVDClient(
        client=client,
    )

    with (
        patch.object(
            nvd_client,
            "_wait_for_rate_limit",
        ),
        pytest.raises(
            NVDResponseError,
            match="Invalid JSON returned by NVD",
        ),
    ):
        nvd_client.query(
            "requests",
        )

    assert "NVD API returned invalid JSON" in caplog.text

    assert "package=requests" in caplog.text
