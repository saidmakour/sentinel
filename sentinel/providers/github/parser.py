from __future__ import annotations

from typing import Any
from typing import cast

from sentinel.providers.github.models import GitHubAdvisory
from sentinel.providers.github.models import GitHubCVSS
from sentinel.providers.github.models import GitHubCVSSSeverities
from sentinel.providers.github.models import GitHubIdentifier
from sentinel.providers.github.models import GitHubPackage
from sentinel.providers.github.models import GitHubVulnerability


class GitHubAdvisoryParser:
    """
    Parse raw GitHub Global Security Advisory payloads.
    """

    def parse(
        self,
        data: dict[str, Any],
    ) -> GitHubAdvisory | None:
        ghsa_id = self._string(data, "ghsa_id")

        if not ghsa_id:
            return None

        return GitHubAdvisory(
            ghsa_id=ghsa_id,
            summary=self._string(data, "summary") or "",
            description=self._string(data, "description"),
            severity=self._string(data, "severity") or "unknown",
            cve_id=self._string(data, "cve_id"),
            identifiers=self._parse_identifiers(
                data.get("identifiers"),
            ),
            vulnerabilities=self._parse_vulnerabilities(
                data.get("vulnerabilities"),
            ),
            cvss=self._parse_cvss(
                data.get("cvss"),
            ),
            cvss_severities=self._parse_cvss_severities(
                data.get("cvss_severities"),
            ),
            published_at=self._string(
                data,
                "published_at",
            ),
            updated_at=self._string(
                data,
                "updated_at",
            ),
            withdrawn_at=self._string(
                data,
                "withdrawn_at",
            ),
            references=self._parse_strings(
                data.get("references"),
            ),
        )

    @staticmethod
    def _string(
        data: dict[str, Any],
        key: str,
    ) -> str | None:
        value = data.get(key)

        if isinstance(value, str):
            return value

        return None

    @staticmethod
    def _parse_strings(
        value: object,
    ) -> list[str]:
        if not isinstance(value, list):
            return []

        items = cast(list[Any], value)

        result: list[str] = []

        for item in items:
            if isinstance(item, str):
                result.append(item)

        return result

    @classmethod
    def _parse_identifiers(
        cls,
        value: object,
    ) -> list[GitHubIdentifier]:
        if not isinstance(value, list):
            return []

        items = cast(list[Any], value)

        result: list[GitHubIdentifier] = []

        for item in items:
            if not isinstance(item, dict):
                continue

            item_data = cast(dict[str, Any], item)

            identifier_type = cls._string(
                item_data,
                "type",
            )
            identifier_value = cls._string(
                item_data,
                "value",
            )

            if not identifier_type or not identifier_value:
                continue

            result.append(
                GitHubIdentifier(
                    type=identifier_type,
                    value=identifier_value,
                ),
            )

        return result

    @classmethod
    def _parse_vulnerabilities(
        cls,
        value: object,
    ) -> list[GitHubVulnerability]:

        if not isinstance(value, list):
            return []

        items = cast(list[Any], value)
        result: list[GitHubVulnerability] = []

        for item in items:
            if not isinstance(item, dict):
                continue

            item_data = cast(dict[str, Any], item)

            package_data = item_data.get("package")

            if not isinstance(package_data, dict):
                continue

            package_data = cast(
                dict[str, Any],
                package_data,
            )

            ecosystem = cls._string(
                package_data,
                "ecosystem",
            )
            package_name = cls._string(
                package_data,
                "name",
            )

            if not ecosystem or not package_name:
                continue

            vulnerable_range = (
                cls._string(
                    item_data,
                    "vulnerable_version_range",
                )
                or ""
            )

            result.append(
                GitHubVulnerability(
                    package=GitHubPackage(
                        ecosystem=ecosystem,
                        name=package_name,
                    ),
                    vulnerable_version_range=vulnerable_range,
                    first_patched_version=cls._string(
                        item_data,
                        "first_patched_version",
                    ),
                    vulnerable_functions=cls._parse_strings(
                        item_data.get(
                            "vulnerable_functions",
                        ),
                    ),
                ),
            )

        return result

    @classmethod
    def _parse_cvss(
        cls,
        value: object,
    ) -> GitHubCVSS | None:
        if not isinstance(value, dict):
            return None

        data = cast(dict[str, Any], value)

        score = data.get("score")

        if not isinstance(score, (int, float)):
            score = None

        vector_string = cls._string(
            data,
            "vector_string",
        )

        if score is None and vector_string is None:
            return None

        return GitHubCVSS(
            score=float(score) if score is not None else None,
            vector_string=vector_string,
        )

    @classmethod
    def _parse_cvss_severities(
        cls,
        value: object,
    ) -> GitHubCVSSSeverities | None:
        if not isinstance(value, dict):
            return None

        data = cast(dict[str, Any], value)

        cvss_v3 = cls._parse_cvss(
            data.get("cvss_v3"),
        )
        cvss_v4 = cls._parse_cvss(
            data.get("cvss_v4"),
        )

        if cvss_v3 is None and cvss_v4 is None:
            return None

        return GitHubCVSSSeverities(
            cvss_v3=cvss_v3,
            cvss_v4=cvss_v4,
        )
