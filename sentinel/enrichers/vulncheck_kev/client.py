from __future__ import annotations

import io
import zipfile
from datetime import datetime
from typing import cast

import httpx

from sentinel.config.settings import settings
from sentinel.enrichers.vulncheck_kev.models import VulnCheckKEVVulnerability
from sentinel.exceptions.enricher import VulnCheckKEVRequestError
from sentinel.exceptions.enricher import VulnCheckKEVResponseError
from sentinel.log.logger import get_logger
from sentinel.providers.base_http_client import BaseHttpClient

logger = get_logger(__name__)

type JSONValue = (
    None
    | bool
    | int
    | float
    | str
    | list["JSONValue"]
    | dict[str, "JSONValue"]
)


class VulnCheckKEVClient(BaseHttpClient):
    """
    Client for the VulnCheck KEV API.
    """

    INDEX = "vulncheck-kev"
    DATA_FILENAME = "vulncheck_known_exploited_vulnerabilities.json"

    def __init__(
        self,
        client: httpx.Client | None = None,
    ) -> None:
        super().__init__(
            timeout=settings.vulncheck_kev_default_timeout,
            client=client,
        )

        self.base_url = (
            f"{settings.vulncheck_kev_base_url}/backup/{self.INDEX}"
        )

        self.api_token = settings.vulncheck_kev_api_token

    def load(
        self,
    ) -> dict[str, VulnCheckKEVVulnerability]:
        """
        Load the VulnCheck KEV catalog.
        """
        logger.warning(
            "Loading VulnCheck KEV catalog.",
        )

        manifest = self._load_manifest()

        backup_url = self._get_backup_url(
            manifest,
        )

        data = self._download_backup(
            backup_url,
        )

        vulnerabilities = self._parse(
            data,
        )

        catalog: dict[str, VulnCheckKEVVulnerability] = {}

        for vulnerability in vulnerabilities:
            for cve_id in vulnerability.cve_ids:
                catalog[cve_id] = vulnerability

        logger.warning(
            "VulnCheck KEV catalog loaded: vulnerabilities=%d",
            len(catalog),
        )

        return catalog

    def _load_manifest(
        self,
    ) -> dict[str, JSONValue]:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_token}",
        }

        try:
            response = self.client.get(
                self.base_url,
                headers=headers,
            )

            response.raise_for_status()

        except httpx.RequestError as exc:
            logger.exception(
                "VulnCheck KEV manifest request failed: url=%s",
                self.base_url,
            )

            raise VulnCheckKEVRequestError(
                str(exc),
            ) from exc

        except httpx.HTTPStatusError as exc:
            logger.exception(
                "VulnCheck KEV manifest returned HTTP error: status=%d url=%s",
                exc.response.status_code,
                self.base_url,
            )

            raise VulnCheckKEVResponseError(
                str(exc),
            ) from exc

        try:
            response_data = response.json()

        except (ValueError, TypeError) as exc:
            logger.exception(
                "VulnCheck KEV manifest contains invalid JSON.",
            )

            raise VulnCheckKEVResponseError(
                "Invalid JSON returned by VulnCheck KEV.",
            ) from exc

        if not isinstance(response_data, dict):
            raise VulnCheckKEVResponseError(
                "Invalid VulnCheck KEV manifest structure.",
            )

        return cast(
            dict[str, JSONValue],
            response_data,
        )

    @classmethod
    def _get_backup_url(
        cls,
        manifest: dict[str, JSONValue],
    ) -> str:
        value = manifest.get("data")

        if not isinstance(value, list) or not value:
            raise VulnCheckKEVResponseError(
                "VulnCheck KEV backup manifest is empty.",
            )

        item = value[0]

        if not isinstance(item, dict):
            raise VulnCheckKEVResponseError(
                "Invalid VulnCheck KEV backup manifest entry.",
            )

        url = item.get("url")

        if not isinstance(url, str) or not url:
            raise VulnCheckKEVResponseError(
                "VulnCheck KEV backup URL is missing.",
            )

        return url

    def _download_backup(
        self,
        url: str,
    ) -> dict[str, JSONValue]:
        logger.debug(
            "Downloading VulnCheck KEV backup.",
        )

        try:
            response = self.client.get(
                url,
            )

            response.raise_for_status()

        except httpx.RequestError as exc:
            logger.exception(
                "VulnCheck KEV backup download failed.",
            )

            raise VulnCheckKEVRequestError(
                str(exc),
            ) from exc

        except httpx.HTTPStatusError as exc:
            logger.exception(
                "VulnCheck KEV backup returned HTTP error: status=%d",
                exc.response.status_code,
            )

            raise VulnCheckKEVResponseError(
                str(exc),
            ) from exc

        try:
            with zipfile.ZipFile(
                io.BytesIO(response.content),
            ) as archive:
                data = archive.read(
                    self.DATA_FILENAME,
                )

        except (
            zipfile.BadZipFile,
            KeyError,
        ) as exc:
            logger.exception(
                "Invalid VulnCheck KEV backup archive.",
            )

            raise VulnCheckKEVResponseError(
                "Invalid VulnCheck KEV backup archive.",
            ) from exc

        try:
            response_data = cast(
                object,
                __import__("json").loads(data),
            )

        except (ValueError, TypeError) as exc:
            logger.exception(
                "VulnCheck KEV backup contains invalid JSON.",
            )

            raise VulnCheckKEVResponseError(
                "Invalid JSON in VulnCheck KEV backup.",
            ) from exc

        if not isinstance(response_data, dict):
            raise VulnCheckKEVResponseError(
                "Invalid VulnCheck KEV backup structure.",
            )

        return cast(
            dict[str, JSONValue],
            response_data,
        )

    def _parse(
        self,
        data: dict[str, JSONValue],
    ) -> list[VulnCheckKEVVulnerability]:
        """
        Parse the VulnCheck KEV response.
        """
        vulnerabilities: list[VulnCheckKEVVulnerability] = []

        for item in self._get_data(data):
            vulnerabilities.append(
                VulnCheckKEVVulnerability(
                    cve_ids=self._parse_cve_ids(
                        item.get("cve"),
                    ),
                    vendor=self._string_value(
                        item,
                        "vendorProject",
                    ),
                    product=self._string_value(
                        item,
                        "product",
                    ),
                    short_description=self._string_value(
                        item,
                        "shortDescription",
                    ),
                    vulnerability_name=self._string_value(
                        item,
                        "vulnerabilityName",
                    ),
                    required_action=self._string_value(
                        item,
                        "required_action",
                    ),
                    known_ransomware=self._string_value(
                        item,
                        "knownRansomwareCampaignUse",
                    ),
                    reported_exploited_by_canaries=self._bool_value(
                        item,
                        "reported_exploited_by_vulncheck_canaries",
                    ),
                    date_added=self._parse_datetime(
                        item.get("date_added"),
                    ),
                    cisa_date_added=self._parse_datetime(
                        item.get("cisa_date_added"),
                    ),
                    due_date=self._parse_datetime(
                        item.get("dueDate"),
                    ),
                ),
            )

        return vulnerabilities

    @staticmethod
    def _get_data(
        data: dict[str, JSONValue],
    ) -> list[dict[str, JSONValue]]:
        value = data.get("data")

        if not isinstance(value, list):
            return []

        items: list[dict[str, JSONValue]] = []

        for item in value:
            if isinstance(item, dict):
                items.append(item)

        return items

    @staticmethod
    def _parse_cve_ids(
        value: JSONValue,
    ) -> list[str]:
        if not isinstance(value, list):
            return []

        cve_ids: list[str] = []

        for item in value:
            if isinstance(item, str):
                cve_ids.append(item)

        return cve_ids

    @staticmethod
    def _parse_datetime(
        value: JSONValue,
    ) -> datetime | None:
        """
        Parse a VulnCheck RFC3339 timestamp.
        """
        if not isinstance(value, str) or not value:
            return None

        try:
            return datetime.fromisoformat(
                value.replace(
                    "Z",
                    "+00:00",
                ),
            )
        except ValueError:
            return None

    @staticmethod
    def _string_value(
        item: dict[str, JSONValue],
        key: str,
    ) -> str:
        value = item.get(key)

        if not isinstance(value, str):
            return ""

        return value

    @staticmethod
    def _bool_value(
        item: dict[str, JSONValue],
        key: str,
    ) -> bool:
        value = item.get(key)

        if not isinstance(value, bool):
            return False

        return value
