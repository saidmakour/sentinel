from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.providers.ghsa.models import GHSAResponse
from sentinel.providers.ghsa.models import GHSAVulnerability


class GHSAMapper:
    def map(
        self,
        dependency: ScannedDependency,
        response: GHSAResponse,
    ) -> list[VulnerabilityInfo]:

        findings: list[VulnerabilityInfo] = []

        for vulnerability in response.vulnerabilities:
            aliases: list[str] = list(
                vulnerability.aliases,
            )

            if vulnerability.cve_id is not None:
                aliases.append(
                    vulnerability.cve_id,
                )

            aliases = list(
                dict.fromkeys(aliases),
            )

            remediation = self._build_remediation(
                vulnerability,
            )

            fixed_versions = [
                rule.fixed
                for rule in remediation.rules
                if rule.fixed is not None
            ]

            findings.append(
                VulnerabilityInfo(
                    dependency_name=dependency.name,
                    dependency_version=dependency.version,
                    ecosystem=dependency.ecosystem,
                    identifier=(vulnerability.cve_id or vulnerability.ghsa_id),
                    aliases=aliases,
                    sources=[
                        Provider.GHSA,
                    ],
                    summary=vulnerability.summary,
                    severity=self._severity(
                        vulnerability.severity,
                    ),
                    cvss=vulnerability.cvss_score,
                    remediation=remediation,
                    fixed_versions=list(
                        dict.fromkeys(
                            fixed_versions,
                        )
                    ),
                )
            )

        return findings

    def _build_remediation(
        self,
        vulnerability: GHSAVulnerability,
    ) -> RemediationInfo:

        if vulnerability.package is None:
            return RemediationInfo()

        package = vulnerability.package

        if (
            package.vulnerable_version_range is None
            and package.first_patched_version is None
        ):
            return RemediationInfo()

        return RemediationInfo(
            rules=[
                RemediationRule(
                    affected_range=(package.vulnerable_version_range),
                    fixed=(package.first_patched_version),
                )
            ]
        )

    def _severity(
        self,
        severity: str,
    ) -> Severity:

        try:
            return Severity(
                severity.upper(),
            )

        except ValueError:
            return Severity.UNKNOWN
