from __future__ import annotations

from typing import Any
from typing import cast

import httpx

from sentinel.config.settings import settings
from sentinel.log.logger import get_logger
from sentinel.providers.base_http_client import BaseHttpClient
from sentinel.providers.ghsa.exceptions import GHSARequestError
from sentinel.providers.ghsa.models import GHSACVSS
from sentinel.providers.ghsa.models import GHSAIdentifier
from sentinel.providers.ghsa.models import GHSAPackage
from sentinel.providers.ghsa.models import GHSAResponse
from sentinel.providers.ghsa.models import GHSAVulnerability

logger = get_logger(__name__)


type JSONObject = dict[str, Any]
type JSONList = list[JSONObject]


class GHSAClient(BaseHttpClient):
    def __init__(
        self,
        client: httpx.Client | None = None,
    ) -> None:
        super().__init__(
            timeout=settings.ghsa_default_timeout,
            client=client,
        )

        self.base_url = settings.ghsa_base_url
        self.token = settings.ghsa_token

    def query(
        self,
        package_name: str,
        ecosystem: str,
    ) -> GHSAResponse:
        ghsa_ecosystem = self._ecosystem_value(ecosystem)
        try:
            response = self.client.get(
                self.base_url,
                params={
                    "ecosystem": ghsa_ecosystem,
                    "affects": package_name,
                },
                headers=self._headers(),
            )

            response.raise_for_status()

        except httpx.RequestError as exc:
            logger.exception(
                "GHSA request failed: package=%s ecosystem=%s",
                package_name,
                ghsa_ecosystem,
            )
            raise GHSARequestError(
                str(exc),
            ) from exc

        except httpx.HTTPStatusError as exc:
            logger.exception(
                "GHSA API returned an HTTP error: "
                "package=%s ecosystem=%s status=%s",
                package_name,
                ghsa_ecosystem,
                exc.response.status_code,
            )
            raise GHSARequestError(
                str(exc),
            ) from exc

        try:
            data = response.json()
        except ValueError as exc:
            logger.exception(
                "GHSA API returned invalid JSON: package=%s ecosystem=%s",
                package_name,
                ghsa_ecosystem,
            )
            raise GHSARequestError("Invalid JSON response") from exc
        logger.debug(
            "GHSA raw response: package=%s ecosystem=%s",
            package_name,
            ghsa_ecosystem,
        )
        if not isinstance(data, list):
            raise GHSARequestError("Invalid GHSA response format")

        parsed_data = cast(list[object], data)

        vulnerabilities: JSONList = []

        for item in parsed_data:
            if not isinstance(item, dict):
                raise GHSARequestError("Invalid GHSA vulnerability format")

            vulnerabilities.append(cast(JSONObject, item))

        return self._parse_response(vulnerabilities)

    def _parse_response(self, data: JSONList) -> GHSAResponse:
        vulnerabilities: list[GHSAVulnerability] = []

        for item in data:
            identifiers = self._parse_identifiers(item.get("identifiers", []))

            package = self._parse_package(item.get("vulnerabilities", []))

            raw_cvss_severities = item.get("cvss_severities", {})

            if isinstance(raw_cvss_severities, dict):
                cvss_severities = cast(
                    JSONObject,
                    raw_cvss_severities,
                )
            else:
                cvss_severities = {}

            raw_cvss_v3 = cvss_severities.get("cvss_v3")
            raw_cvss_v4 = cvss_severities.get("cvss_v4")

            cvss_v3 = self._parse_cvss(raw_cvss_v3)
            cvss_v4 = self._parse_cvss(raw_cvss_v4)

            vulnerabilities.append(
                GHSAVulnerability(
                    ghsa_id=str(item.get("ghsa_id", "")),
                    cve_id=self._optional_string(item.get("cve_id")),
                    summary=str(item.get("summary", "")),
                    description=str(item.get("description", "")),
                    severity=str(item.get("severity", "")),
                    identifiers=identifiers,
                    package=package,
                    cvss_v3=cvss_v3,
                    cvss_v4=cvss_v4,
                )
            )

        return GHSAResponse(vulnerabilities=vulnerabilities)

    def _parse_identifiers(self, data: object) -> list[GHSAIdentifier]:
        if not isinstance(data, list):
            return []

        raw_identifiers = cast(list[object], data)
        identifiers: list[GHSAIdentifier] = []

        for identifier in raw_identifiers:
            if isinstance(identifier, dict):
                identifier_data = cast(JSONObject, identifier)

                identifiers.append(
                    GHSAIdentifier(
                        type=str(identifier_data.get("type", "")),
                        value=str(identifier_data.get("value", "")),
                    )
                )

            elif isinstance(identifier, str):
                identifiers.append(
                    GHSAIdentifier(
                        type="",
                        value=identifier,
                    )
                )

        return identifiers

    def _parse_package(self, data: object) -> GHSAPackage | None:
        if not isinstance(data, list) or not data:
            return None

        raw_vulnerabilities = cast(list[object], data)
        first = raw_vulnerabilities[0]

        if not isinstance(first, dict):
            return None

        first_data = cast(JSONObject, first)

        package_data = first_data.get("package", {})

        if not isinstance(package_data, dict):
            package_data = {}

        package = cast(JSONObject, package_data)

        return GHSAPackage(
            ecosystem=str(package.get("ecosystem", "")),
            name=str(package.get("name", "")),
            first_patched_version=self._optional_string(
                first_data.get("first_patched_version")
            ),
            vulnerable_version_range=self._optional_string(
                first_data.get("vulnerable_version_range")
            ),
        )

    def _parse_cvss(
        self,
        data: object,
    ) -> GHSACVSS | None:
        if not isinstance(data, dict):
            return None

        cvss = cast(
            dict[str, Any],
            data,
        )

        return GHSACVSS(
            vector_string=self._optional_string(
                cvss.get(
                    "vector_string",
                )
            ),
            score=self._optional_float(
                cvss.get(
                    "score",
                )
            ),
        )

    @staticmethod
    def _optional_string(
        value: Any,
    ) -> str | None:
        if value is None:
            return None

        if isinstance(value, str):
            return value

        return str(value)

    @staticmethod
    def _optional_float(
        value: Any,
    ) -> float | None:
        if value is None:
            return None

        if isinstance(value, (int, float)):
            return float(value)

        return None

    def _headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": "Sentinel",
            "Content-Type": "application/json",
        }

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        return headers

    @staticmethod
    def _ecosystem_value(ecosystem: str) -> str:
        mapping = {
            "PyPI": "pip",
            "NPM": "npm",
            "Maven": "maven",
            "NuGet": "nuget",
            "Composer": "composer",
            "Go": "go",
            "RubyGems": "rubygems",
            "Rust": "rust",
            "Erlang": "erlang",
            "Pub": "pub",
            "Swift": "swift",
        }

        return mapping.get(ecosystem, ecosystem.lower())
