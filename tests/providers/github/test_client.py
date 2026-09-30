from unittest.mock import MagicMock

import httpx
import pytest

from sentinel.providers.github.client import GitHubAdvisoryClient
from sentinel.providers.github.client import GitHubAdvisoryRequestError
from sentinel.providers.github.client import GitHubAdvisoryResponseError


def create_client() -> tuple[GitHubAdvisoryClient, MagicMock]:
    http_client = MagicMock(spec=httpx.Client)

    client = GitHubAdvisoryClient(
        token="test-token",
        client=http_client,
    )

    return client, http_client


def test_client_uses_settings() -> None:
    client = GitHubAdvisoryClient()

    assert client.base_url == "https://api.github.com"


def test_client_builds_authorization_header() -> None:
    client = GitHubAdvisoryClient(
        token="test-token",
    )

    assert client._headers == {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Sentinel",
        "Authorization": "Bearer test-token",
    }


def test_client_does_not_add_authorization_without_token() -> None:
    client = GitHubAdvisoryClient(
        token="",
    )

    assert client._headers == {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Sentinel",
    }


def test_query_returns_advisories() -> None:
    client, http_client = create_client()

    advisories = [
        {
            "ghsa_id": "GHSA-test-1234",
            "cve_id": "CVE-2026-1234",
            "summary": "Test vulnerability",
        },
    ]

    response = MagicMock()
    response.json.return_value = advisories

    http_client.get.return_value = response

    result = client.query(
        package_name="requests",
        version="2.31.0",
        ecosystem="pip",
    )

    assert result == advisories

    http_client.get.assert_called_once_with(
        f"{client.base_url}/advisories",
        params={
            "affects": "requests@2.31.0",
            "ecosystem": "pip",
            "type": "reviewed",
            "per_page": 100,
        },
        headers=client._headers,
    )

    response.raise_for_status.assert_called_once()


def test_query_builds_affects_parameter() -> None:
    client, http_client = create_client()

    response = MagicMock()
    response.json.return_value = []

    http_client.get.return_value = response

    client.query(
        package_name="org.example/library",
        version="1.2.3",
        ecosystem="maven",
    )

    http_client.get.assert_called_once_with(
        f"{client.base_url}/advisories",
        params={
            "affects": "org.example/library@1.2.3",
            "ecosystem": "maven",
            "type": "reviewed",
            "per_page": 100,
        },
        headers=client._headers,
    )


def test_query_returns_empty_list() -> None:
    client, http_client = create_client()

    response = MagicMock()
    response.json.return_value = []

    http_client.get.return_value = response

    result = client.query(
        package_name="requests",
        version="999.0.0",
        ecosystem="pip",
    )

    assert result == []


def test_query_filters_non_dict_items() -> None:
    client, http_client = create_client()

    response = MagicMock()
    response.json.return_value = [
        {
            "ghsa_id": "GHSA-test-1234",
        },
        "invalid",
        None,
        123,
    ]

    http_client.get.return_value = response

    result = client.query(
        package_name="requests",
        version="2.31.0",
        ecosystem="pip",
    )

    assert result == [
        {
            "ghsa_id": "GHSA-test-1234",
        },
    ]


def test_query_raises_request_error() -> None:
    client, http_client = create_client()

    http_client.get.side_effect = httpx.RequestError(
        "connection failed",
    )

    with pytest.raises(
        GitHubAdvisoryRequestError,
        match="connection failed",
    ):
        client.query(
            package_name="requests",
            version="2.31.0",
            ecosystem="pip",
        )


def test_query_raises_response_error() -> None:
    client, http_client = create_client()

    response = MagicMock()
    response.status_code = 401

    error = httpx.HTTPStatusError(
        "unauthorized",
        request=MagicMock(),
        response=response,
    )

    response.raise_for_status.side_effect = error
    http_client.get.return_value = response

    with pytest.raises(
        GitHubAdvisoryResponseError,
        match="GitHub Advisory returned HTTP 401",
    ):
        client.query(
            package_name="requests",
            version="2.31.0",
            ecosystem="pip",
        )


def test_query_raises_invalid_json() -> None:
    client, http_client = create_client()

    response = MagicMock()
    response.json.side_effect = ValueError("invalid json")

    http_client.get.return_value = response

    with pytest.raises(
        GitHubAdvisoryResponseError,
        match="GitHub Advisory returned invalid JSON",
    ):
        client.query(
            package_name="requests",
            version="2.31.0",
            ecosystem="pip",
        )


def test_query_raises_unexpected_response() -> None:
    client, http_client = create_client()

    response = MagicMock()
    response.json.return_value = {
        "message": "Bad credentials",
    }

    http_client.get.return_value = response

    with pytest.raises(
        GitHubAdvisoryResponseError,
        match="GitHub Advisory returned an unexpected response",
    ):
        client.query(
            package_name="requests",
            version="2.31.0",
            ecosystem="pip",
        )
