from __future__ import annotations

from typing import Any
from typing import cast

import httpx

from sentinel.config.settings import settings
from sentinel.providers.base_http_client import BaseHttpClient


class GitHubAdvisoryRequestError(RuntimeError):
    """
    Raised when a GitHub Advisory request cannot be completed.
    """


class GitHubAdvisoryResponseError(RuntimeError):
    """
    Raised when GitHub returns an invalid advisory response.
    """


def _parse_advisories(data: object) -> list[dict[str, Any]]:
    if not isinstance(data, list):
        raise GitHubAdvisoryResponseError(
            "GitHub Advisory returned an unexpected response",
        )

    items = cast(list[Any], data)

    advisories: list[dict[str, Any]] = []

    for item in items:
        if isinstance(item, dict):
            advisories.append(
                cast(dict[str, Any], item),
            )

    return advisories


class GitHubAdvisoryClient(BaseHttpClient):
    """
    Client for the GitHub Global Security Advisory REST API.
    """

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        timeout: int | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        super().__init__(
            timeout=timeout or settings.github_advisory_default_timeout,
            client=client,
        )

        self.base_url = (base_url or settings.github_advisory_base_url).rstrip(
            "/"
        )

        self.token = (
            token if token is not None else settings.github_advisory_token
        )

    @property
    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "Sentinel",
        }

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        return headers

    def query(
        self,
        package_name: str,
        version: str,
        ecosystem: str,
    ) -> list[dict[str, Any]]:
        """
        Search GitHub Global Security Advisories.

        The ``affects`` parameter is used with package@version so that
        GitHub returns advisories affecting the specific dependency version.
        """
        url = f"{self.base_url}/advisories"

        params: dict[str, str | int] = {
            "affects": f"{package_name}@{version}",
            "ecosystem": ecosystem,
            "type": "reviewed",
            "per_page": 100,
        }

        try:
            response = self.client.get(
                url,
                params=params,
                headers=self._headers,
            )
            response.raise_for_status()

        except httpx.RequestError as exc:
            raise GitHubAdvisoryRequestError(
                f"GitHub Advisory request failed: {exc}",
            ) from exc

        except httpx.HTTPStatusError as exc:
            raise GitHubAdvisoryResponseError(
                f"GitHub Advisory returned HTTP {exc.response.status_code}",
            ) from exc

        try:
            data: object = response.json()
        except ValueError as exc:
            raise GitHubAdvisoryResponseError(
                "GitHub Advisory returned invalid JSON",
            ) from exc

        return _parse_advisories(data)
