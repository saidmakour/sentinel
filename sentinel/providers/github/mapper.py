from __future__ import annotations

from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.providers.github.models import GitHubAdvisory


class GitHubAdvisoryMapper:
    """
    Maps GitHub Global Security Advisory models to Sentinel DTOs.
    """

    def map(
        self,
        dependency: ScannedDependency,
        advisories: list[GitHubAdvisory],
    ) -> list[VulnerabilityInfo]:
        return [
            self._map_advisory(
                advisory=advisory,
                dependency=dependency,
            )
            for advisory in advisories
        ]

    def _map_advisory(
        self,
        advisory: GitHubAdvisory,
        dependency: ScannedDependency,
    ) -> VulnerabilityInfo:
        return VulnerabilityInfo(
            dependency_name=dependency.name,
            dependency_version=dependency.version,
            ecosystem=dependency.ecosystem,
            identifier=self._get_identifier(advisory),
            aliases=self._get_aliases(advisory),
            sources=[Provider.GITHUB_ADVISORY],
            summary=advisory.summary,
            severity=self._map_severity(advisory.severity),
            cvss=self._get_cvss_score(advisory),
            fixed_versions=self._get_fixed_versions(advisory),
            remediation=self._get_remediation(advisory),
        )

    @staticmethod
    def _get_identifier(
        advisory: GitHubAdvisory,
    ) -> str:
        """
        Prefer CVE as the primary identifier when available.
        """
        if advisory.cve_id:
            return advisory.cve_id

        return advisory.ghsa_id

    @staticmethod
    def _get_aliases(
        advisory: GitHubAdvisory,
    ) -> list[str]:
        """
        Build a unique list of GHSA, CVE and other identifiers.
        """
        aliases: list[str] = []

        for value in (
            advisory.ghsa_id,
            advisory.cve_id,
        ):
            if value and value not in aliases:
                aliases.append(value)

        for identifier in advisory.identifiers:
            if identifier.value not in aliases:
                aliases.append(identifier.value)

        return aliases

    @staticmethod
    def _get_cvss_score(
        advisory: GitHubAdvisory,
    ) -> float | None:
        """
        Return the highest available CVSS score.

        GitHub can expose both CVSS v3 and v4 scores. The top-level
        ``cvss`` field is also considered as a fallback.
        """
        scores: list[float] = []

        if advisory.cvss_severities is not None:
            for cvss in (
                advisory.cvss_severities.cvss_v4,
                advisory.cvss_severities.cvss_v3,
            ):
                if cvss is not None and cvss.score is not None:
                    scores.append(cvss.score)

        if advisory.cvss is not None and advisory.cvss.score is not None:
            scores.append(advisory.cvss.score)

        if not scores:
            return None

        return max(scores)

    @staticmethod
    def _get_fixed_versions(
        advisory: GitHubAdvisory,
    ) -> list[str]:
        """
        Extract unique first patched versions.
        """
        versions: list[str] = []

        for vulnerability in advisory.vulnerabilities:
            version = vulnerability.first_patched_version

            if version and version not in versions:
                versions.append(version)

        return versions

    @staticmethod
    def _map_severity(
        value: str,
    ) -> Severity:
        """
        Map GitHub severity values to Sentinel severity values.
        """
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "moderate": Severity.MEDIUM,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }

        return mapping.get(
            value.lower(),
            Severity.UNKNOWN,
        )

    def _get_remediation(
        self,
        advisory: GitHubAdvisory,
    ) -> RemediationInfo:
        rules = [
            RemediationRule(
                affected_range=vulnerability.vulnerable_version_range,
                fixed=vulnerability.first_patched_version,
            )
            for vulnerability in advisory.vulnerabilities
            if vulnerability.vulnerable_version_range
            or vulnerability.first_patched_version
        ]

        return RemediationInfo(rules=rules)
