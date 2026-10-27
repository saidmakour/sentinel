from __future__ import annotations

from typing import Any

import httpx

from sentinel.config.settings import settings
from sentinel.log.logger import get_logger
from sentinel.providers.base_http_client import BaseHttpClient
from sentinel.providers.osv.models import OSVAffected
from sentinel.providers.osv.models import OSVEvent
from sentinel.providers.osv.models import OSVRange
from sentinel.providers.osv.models import OSVResponse
from sentinel.providers.osv.models import OSVSeverity
from sentinel.providers.osv.models import OSVVulnerability

logger = get_logger(__name__)


class OSVClient(BaseHttpClient):
    def __init__(
        self,
        client: httpx.Client | None = None,
    ) -> None:

        super().__init__(
            timeout=settings.osv_default_timeout,
            client=client,
        )

        self.base_url = settings.osv_base_url

    def query(
        self,
        package_name: str,
        version: str,
        ecosystem: str,
    ) -> OSVResponse:

        logger.debug(
            "Querying OSV: package=%s version=%s ecosystem=%s",
            package_name,
            version,
            ecosystem,
        )

        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            },
            "version": version,
        }

        response = self.client.post(
            self.base_url,
            json=payload,
        )

        response.raise_for_status()

        result = self._parse_response(
            dict(response.json()),
        )

        logger.debug(
            "OSV RESULT: package=%s version=%s ecosystem=%s vulnerabilities=%s",
            package_name,
            version,
            ecosystem,
            [
                (
                    vuln.identifier,
                    vuln.aliases,
                    [
                        (
                            rule.introduced,
                            rule.fixed,
                            rule.affected_range,
                        )
                        for rule in vuln.remediation.rules
                    ],
                )
                for vuln in result.vulns
            ],
        )
        logger.debug(
            "OSV query completed: package=%s version=%s vulnerabilities=%d",
            package_name,
            version,
            len(result.vulns),
        )

        return result

    def _parse_response(
        self,
        data: dict[str, Any],
    ) -> OSVResponse:

        vulnerabilities: list[OSVVulnerability] = []

        for item in data.get("vulns", []):
            severities = [
                OSVSeverity(
                    type=severity.get("type", ""),
                    score=severity.get("score", ""),
                )
                for severity in item.get("severity", [])
            ]

            affected = [
                OSVAffected(
                    package_name=affected_item.get(
                        "package",
                        {},
                    ).get(
                        "name",
                        "",
                    ),
                    ranges=[
                        OSVRange(
                            type=range_item.get(
                                "type",
                                "",
                            ),
                            events=[
                                OSVEvent(
                                    introduced=event.get(
                                        "introduced",
                                    ),
                                    fixed=event.get(
                                        "fixed",
                                    ),
                                )
                                for event in range_item.get(
                                    "events",
                                    [],
                                )
                            ],
                        )
                        for range_item in affected_item.get(
                            "ranges",
                            [],
                        )
                    ],
                )
                for affected_item in item.get(
                    "affected",
                    [],
                )
            ]

            vulnerabilities.append(
                OSVVulnerability(
                    identifier=item.get(
                        "id",
                        "",
                    ),
                    aliases=[
                        str(alias)
                        for alias in item.get(
                            "aliases",
                            [],
                        )
                        if alias
                    ],
                    summary=item.get(
                        "summary",
                        "",
                    ),
                    severity=severities,
                    affected=affected,
                )
            )

        return OSVResponse(
            vulns=vulnerabilities,
        )
