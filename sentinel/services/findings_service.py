from datetime import datetime

from sqlalchemy.orm import Session

from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.models.finding import Finding
from sentinel.repositories.finding_repository import FindingRepository
from sentinel.services.finding_normalizer import FindingNormalizer


class FindingService:
    """
    Provides normalized vulnerability findings for completed scans.
    """

    def __init__(
        self,
        session: Session,
        normalizer: FindingNormalizer | None = None,
    ) -> None:
        self.repository = FindingRepository(session)
        self.normalizer = normalizer or FindingNormalizer()

    def _to_vulnerability_info(
        self,
        finding: Finding,
    ) -> VulnerabilityInfo:

        sources = [Provider(source) for source in finding.sources]

        remediation = None

        if finding.remediation is not None:
            rules = [
                RemediationRule(
                    introduced=rule["introduced"],
                    fixed=rule["fixed"],
                    affected_range=rule["affected_range"],
                )
                for rule in finding.remediation["rules"]
            ]

            remediation = RemediationInfo(
                rules=rules,
            )

        return VulnerabilityInfo(
            dependency_name=finding.dependency_name,
            dependency_version=finding.dependency_version,
            ecosystem=finding.ecosystem,
            identifier=finding.identifier,
            aliases=finding.aliases,
            sources=sources,
            summary=finding.summary,
            severity=Severity(finding.severity),
            cvss=finding.cvss,
            status=VulnerabilityStatus(finding.status),
            remediation=remediation,
            fixed_versions=finding.fixed_versions,
            known_exploited=finding.known_exploited,
            kev_date_added=finding.kev_date_added,
            kev_vendor=finding.kev_vendor,
            kev_product=finding.kev_product,
            kev_required_action=finding.kev_required_action,
            kev_known_ransomware=finding.kev_known_ransomware,
            vulncheck_known_exploited=finding.vulncheck_known_exploited,
            vulncheck_date_added=(
                datetime.combine(
                    finding.vulncheck_date_added,
                    datetime.min.time(),
                )
                if finding.vulncheck_date_added is not None
                else None
            ),
            vulncheck_cisa_date_added=(
                datetime.combine(
                    finding.vulncheck_cisa_date_added,
                    datetime.min.time(),
                )
                if finding.vulncheck_cisa_date_added is not None
                else None
            ),
            vulncheck_due_date=(
                datetime.combine(
                    finding.vulncheck_due_date,
                    datetime.min.time(),
                )
                if finding.vulncheck_due_date is not None
                else None
            ),
            vulncheck_vendor=finding.vulncheck_vendor,
            vulncheck_product=finding.vulncheck_product,
            vulncheck_required_action=finding.vulncheck_required_action,
            vulncheck_known_ransomware=finding.vulncheck_known_ransomware,
            vulncheck_reported_exploited_by_canaries=(
                finding.vulncheck_reported_exploited_by_canaries
            ),
            epss_score=finding.epss_score,
            epss_percentile=finding.epss_percentile,
        )

    def list_by_scan(
        self,
        scan_id: int,
    ) -> list[VulnerabilityInfo]:

        findings = self.repository.list_by_scan(
            scan_id,
        )

        vulnerabilities = [
            self._to_vulnerability_info(
                finding,
            )
            for finding in findings
        ]

        return self.normalizer.normalize(
            vulnerabilities,
        )
