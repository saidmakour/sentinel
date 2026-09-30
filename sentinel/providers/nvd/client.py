from __future__ import annotations

import threading
import time
from typing import Any
from typing import TypedDict
from typing import cast

import httpx

from sentinel.config.settings import settings
from sentinel.log.logger import get_logger
from sentinel.providers.base_http_client import BaseHttpClient
from sentinel.providers.nvd.exceptions import NVDRequestError
from sentinel.providers.nvd.exceptions import NVDResponseError
from sentinel.providers.nvd.models import NVDMetric
from sentinel.providers.nvd.models import NVDResponse
from sentinel.providers.nvd.models import NVDVersionRange
from sentinel.providers.nvd.models import NVDVulnerability

logger = get_logger(__name__)


class NVDCPEMatchData(TypedDict, total=False):
    criteria: str
    versionStartIncluding: str
    versionStartExcluding: str
    versionEndIncluding: str
    versionEndExcluding: str


class NVDNodeData(TypedDict, total=False):
    cpeMatch: list[NVDCPEMatchData]


class NVDConfigurationData(TypedDict, total=False):
    nodes: list[NVDNodeData]


class NVDClient(BaseHttpClient):
    def __init__(
        self,
        client: httpx.Client | None = None,
    ) -> None:
        super().__init__(
            timeout=settings.nvd_default_timeout,
            client=client,
        )

        self.base_url = settings.nvd_base_url
        self.api_key = settings.nvd_api_key

        self.min_request_interval: float = settings.nvd_min_request_interval
        self.max_retries: int = settings.nvd_max_retries
        self.retry_backoff: float = settings.nvd_retry_backoff

        self._rate_limit_lock = threading.Lock()
        self._last_request_time = 0.0

    def query(
        self,
        package_name: str,
    ) -> NVDResponse:
        for attempt in range(
            self.max_retries + 1,
        ):
            self._wait_for_rate_limit()

            try:
                keyword = self._build_keyword(
                    package_name,
                )

                logger.debug(
                    "NVD query keyword=%s package=%s",
                    keyword,
                    package_name,
                )

                response = self.client.get(
                    self.base_url,
                    headers=self._headers(),
                    params={
                        "keywordSearch": keyword,
                    },
                )

                if response.status_code == 429:
                    if attempt >= self.max_retries:
                        logger.error(
                            "NVD rate limit exceeded after retries: "
                            "package=%s attempts=%d",
                            package_name,
                            attempt + 1,
                        )
                        raise NVDResponseError(
                            "NVD rate limit exceeded after "
                            f"{attempt + 1} attempts."
                        )

                    retry_after = self._retry_after(
                        response,
                    )

                    delay = self._retry_delay(
                        attempt,
                        retry_after,
                    )

                    logger.debug(
                        "NVD rate limit reached: "
                        "package=%s attempt=%d/%d retry_in=%.2fs",
                        package_name,
                        attempt + 1,
                        self.max_retries + 1,
                        delay,
                    )

                    time.sleep(
                        delay,
                    )

                    continue

                response.raise_for_status()

            except httpx.RequestError as exc:
                logger.exception(
                    "NVD request failed: package=%s",
                    package_name,
                )
                raise NVDRequestError(
                    str(exc),
                ) from exc

            except httpx.HTTPStatusError as exc:
                logger.exception(
                    "NVD API returned an HTTP error: package=%s status=%s",
                    package_name,
                    exc.response.status_code,
                )
                raise NVDResponseError(
                    str(exc),
                ) from exc

            try:
                data = response.json()

            except (ValueError, TypeError) as exc:
                logger.exception(
                    "NVD API returned invalid JSON: package=%s",
                    package_name,
                )
                raise NVDResponseError(
                    "Invalid JSON returned by NVD.",
                ) from exc

            return self._parse(
                data,
            )

        raise NVDResponseError(
            "NVD request failed unexpectedly.",
        )

    def _wait_for_rate_limit(
        self,
    ) -> None:
        with self._rate_limit_lock:
            now = time.monotonic()

            elapsed = now - self._last_request_time

            remaining = self.min_request_interval - elapsed

            if remaining > 0:
                time.sleep(
                    remaining,
                )

            self._last_request_time = time.monotonic()

    def _retry_after(
        self,
        response: httpx.Response,
    ) -> float | None:
        value = response.headers.get(
            "Retry-After",
        )

        if value is None:
            return None

        try:
            return float(
                value,
            )
        except ValueError:
            return None

    def _retry_delay(
        self,
        attempt: int,
        retry_after: float | None,
    ) -> float:
        backoff: float = self.retry_backoff * (2**attempt)

        if retry_after is not None:
            return max(
                retry_after,
                backoff,
            )

        return backoff

    def _headers(
        self,
    ) -> dict[str, str]:
        headers = {
            "User-Agent": "Sentinel",
        }

        if self.api_key:
            headers["apiKey"] = self.api_key

        return headers

    def _parse(
        self,
        data: dict[str, Any],
    ) -> NVDResponse:
        return NVDResponse(
            vulnerabilities=[
                self._parse_vulnerability(item)
                for item in data.get(
                    "vulnerabilities",
                    [],
                )
            ]
        )

    def _parse_vulnerability(
        self,
        data: dict[str, Any],
    ) -> NVDVulnerability:
        cve = data.get(
            "cve",
            {},
        )

        vulnerability = NVDVulnerability(
            identifier=cve.get(
                "id",
                "",
            ),
            aliases=self._extract_aliases(
                cve.get(
                    "references",
                    [],
                ),
            ),
            summary=self._extract_summary(
                cve.get(
                    "descriptions",
                    [],
                )
            ),
            metric=NVDMetric(
                score=self._extract_cvss_score(
                    cve,
                )
            ),
            configurations=self._extract_configurations(
                cve,
            ),
        )

        return vulnerability

    def _extract_summary(
        self,
        descriptions: list[dict[str, Any]],
    ) -> str:
        for description in descriptions:
            if description.get("lang") == "en":
                return str(
                    description.get(
                        "value",
                        "",
                    )
                )

        return ""

    def _extract_cvss_score(
        self,
        cve: dict[str, Any],
    ) -> float | None:
        metrics = cve.get(
            "metrics",
            {},
        )

        for key in (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ):
            values = metrics.get(
                key,
                [],
            )

            if values:
                cvss = values[0].get(
                    "cvssData",
                    {},
                )

                score = cvss.get(
                    "baseScore",
                )

                if score is not None:
                    try:
                        return float(
                            score,
                        )
                    except (
                        TypeError,
                        ValueError,
                    ):
                        return None

        return None

    def _extract_aliases(
        self,
        references: list[dict[str, Any]],
    ) -> list[str]:
        aliases: list[str] = []

        for reference in references:
            url = str(
                reference.get(
                    "url",
                    "",
                )
            )

            for part in url.split("/"):
                if part.startswith("GHSA-"):
                    aliases.append(
                        part,
                    )

        return list(
            dict.fromkeys(
                aliases,
            )
        )

    def _build_keyword(
        self,
        package_name: str,
    ) -> str:
        """
        Build NVD keywordSearch from package name.

        Examples:
            brick/math
            -> "brick math"

            guzzlehttp/guzzle
            -> "guzzlehttp guzzle"

            symfony/http-foundation
            -> "symfony http foundation"
        """

        return (
            package_name.lower()
            .replace("/", " ")
            .replace("-", " ")
            .replace("_", " ")
        )

    def _extract_configurations(
        self,
        cve: dict[str, Any],
    ) -> list[NVDVersionRange]:
        raw_configurations = cve.get(
            "configurations",
            [],
        )

        if not isinstance(
            raw_configurations,
            list,
        ):
            return []

        configurations = cast(
            list[NVDConfigurationData],
            raw_configurations,
        )

        results: list[NVDVersionRange] = []

        for configuration in configurations:
            nodes = configuration.get(
                "nodes",
                [],
            )

            for node in nodes:
                cpe_matches = node.get(
                    "cpeMatch",
                    [],
                )

                for match in cpe_matches:
                    parsed = self._parse_cpe_match(
                        match,
                    )

                    if parsed is not None:
                        results.append(parsed)

        return results

    def _parse_cpe_match(
        self,
        match: NVDCPEMatchData,
    ) -> NVDVersionRange | None:
        criteria = match.get("criteria")

        if not criteria:
            return None

        return NVDVersionRange(
            criteria=criteria,
            version_start_including=match.get(
                "versionStartIncluding",
            ),
            version_start_excluding=match.get(
                "versionStartExcluding",
            ),
            version_end_including=match.get(
                "versionEndIncluding",
            ),
            version_end_excluding=match.get(
                "versionEndExcluding",
            ),
        )
