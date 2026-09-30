from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.provider import Provider
from sentinel.providers.osv.models import OSVResponse
from sentinel.utils.severity import severity_from_cvss


class OSVMapper:
    def map(
        self,
        dependency: ScannedDependency,
        response: OSVResponse,
    ) -> list[VulnerabilityInfo]:
        results: list[VulnerabilityInfo] = []

        for vuln in response.vulns:
            results.append(
                VulnerabilityInfo(
                    identifier=vuln.identifier,
                    aliases=vuln.aliases,
                    dependency_name=dependency.name,
                    dependency_version=dependency.version,
                    ecosystem=dependency.ecosystem,
                    sources=[Provider.OSV],
                    severity=severity_from_cvss(
                        vuln.cvss,
                    ),
                    cvss=vuln.cvss,
                    summary=vuln.summary,
                    fixed_versions=vuln.fixed_versions,
                    remediation=vuln.remediation,
                )
            )

        return results
