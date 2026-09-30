from __future__ import annotations

from datetime import date
from typing import Any

import httpx

from sentinel.config.settings import settings
from sentinel.enrichers.kev.models import KEVResponse
from sentinel.enrichers.kev.models import KEVVulnerability
from sentinel.exceptions.enricher import KEVRequestError
from sentinel.exceptions.enricher import KEVResponseError
from sentinel.log.logger import get_logger
from sentinel.providers.base_http_client import BaseHttpClient

logger = get_logger(__name__)


class KEVClient(BaseHttpClient):
    def __init__(
        self,
        client: httpx.Client | None = None,
    ) -> None:
        super().__init__(
            timeout=settings.kev_default_timeout,
            client=client,
        )

        self.base_url = settings.kev_base_url

    def load(
        self,
    ) -> dict[str, KEVVulnerability]:

        logger.debug(
            "Loading CISA KEV catalog.",
        )

        try:
            response = self.client.get(
                self.base_url,
            )

            response.raise_for_status()

        except httpx.RequestError as exc:
            logger.exception(
                "KEV request failed: url=%s",
                self.base_url,
            )

            raise KEVRequestError(
                str(exc),
            ) from exc

        except httpx.HTTPStatusError as exc:
            logger.exception(
                "KEV request returned HTTP error: status=%d url=%s",
                exc.response.status_code,
                self.base_url,
            )

            raise KEVResponseError(
                str(exc),
            ) from exc

        try:
            data = self._parse(
                dict(response.json()),
            )

        except (ValueError, TypeError) as exc:
            logger.exception(
                "KEV response contains invalid JSON.",
            )

            raise KEVResponseError(
                "Invalid JSON returned by KEV.",
            ) from exc

        vulnerabilities = {
            vulnerability.cve_id: vulnerability
            for vulnerability in data.vulnerabilities
        }

        logger.debug(
            "KEV catalog loaded: vulnerabilities=%d",
            len(vulnerabilities),
        )

        return vulnerabilities

    def _parse(
        self,
        data: dict[str, Any],
    ) -> KEVResponse:

        vulnerabilities: list[KEVVulnerability] = []

        for item in data.get(
            "vulnerabilities",
            [],
        ):
            vulnerabilities.append(
                KEVVulnerability(
                    cve_id=item.get(
                        "cveID",
                        "",
                    ),
                    date_added=self._parse_date(
                        item.get("dateAdded"),
                    ),
                    due_date=self._parse_date(
                        item.get("dueDate"),
                    ),
                    vendor=item.get(
                        "vendorProject",
                        "",
                    ),
                    product=item.get(
                        "product",
                        "",
                    ),
                    required_action=item.get(
                        "requiredAction",
                        "",
                    ),
                    known_ransomware=item.get(
                        "knownRansomwareCampaignUse",
                        "",
                    ),
                )
            )

        return KEVResponse(
            vulnerabilities=vulnerabilities,
        )

    @staticmethod
    def _parse_date(
        value: str | None,
    ) -> date | None:

        if not value:
            return None

        return date.fromisoformat(value)
