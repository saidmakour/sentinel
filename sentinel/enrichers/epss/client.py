from __future__ import annotations

from typing import Any

import httpx

from sentinel.config.settings import settings
from sentinel.enrichers.epss.models import EPSSResponse
from sentinel.enrichers.epss.models import EPSSScore
from sentinel.log.logger import get_logger
from sentinel.providers.base_http_client import BaseHttpClient

logger = get_logger(__name__)


class EPSSClient(BaseHttpClient):
    BATCH_SIZE = settings.epss_batch_size

    def __init__(
        self,
        client: httpx.Client | None = None,
    ) -> None:
        super().__init__(
            timeout=settings.epss_default_timeout,
            client=client,
        )

        self.base_url = settings.epss_base_url

    def load(
        self,
        identifiers: list[str],
    ) -> dict[str, EPSSScore]:

        if not identifiers:
            logger.debug(
                "Skipping EPSS query: no identifiers.",
            )
            return {}

        logger.debug(
            "Loading EPSS scores: identifiers=%d batch_size=%d",
            len(identifiers),
            self.BATCH_SIZE,
        )

        scores: dict[str, EPSSScore] = {}

        batches = self._chunks(
            identifiers,
            self.BATCH_SIZE,
        )

        for index, batch in enumerate(
            batches,
            start=1,
        ):
            logger.debug(
                "Querying EPSS batch: batch=%d/%d identifiers=%d",
                index,
                len(batches),
                len(batch),
            )

            response = self.client.get(
                self.base_url,
                params={
                    "cve": ",".join(batch),
                },
            )

            response.raise_for_status()

            epss = self._parse_response(
                dict(response.json()),
            )

            scores.update({score.cve: score for score in epss.scores})

            logger.debug(
                "EPSS batch completed: batch=%d/%d scores=%d",
                index,
                len(batches),
                len(epss.scores),
            )

        logger.debug(
            "EPSS loading completed: identifiers=%d scores=%d",
            len(identifiers),
            len(scores),
        )

        return scores

    @staticmethod
    def _chunks(
        identifiers: list[str],
        size: int,
    ) -> list[list[str]]:
        return [
            identifiers[index : index + size]
            for index in range(
                0,
                len(identifiers),
                size,
            )
        ]

    def _parse_response(
        self,
        data: dict[str, Any],
    ) -> EPSSResponse:

        scores: list[EPSSScore] = []

        for item in data.get("data", []):
            scores.append(
                EPSSScore(
                    cve=item.get("cve", ""),
                    score=float(
                        item.get("epss", 0.0),
                    ),
                    percentile=float(
                        item.get("percentile", 0.0),
                    ),
                )
            )

        return EPSSResponse(
            scores=scores,
        )
