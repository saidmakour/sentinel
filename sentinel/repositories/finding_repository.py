from collections import Counter

from sqlalchemy.orm import Session

from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.models.finding import Finding
from sentinel.models.scan import Scan


class FindingRepository:
    """
    Handles persistence of Finding objects.
    """

    def __init__(
        self,
        session: Session,
    ):
        self.session = session

    def create(
        self,
        finding: Finding,
    ) -> Finding:

        self.session.add(finding)
        self.session.flush()

        return finding

    def add_many(
        self,
        findings: list[VulnerabilityInfo],
        scan_id: int,
    ) -> None:
        """
        Persist vulnerability findings.
        """

        models = [
            Finding(
                scan_id=scan_id,
                dependency_name=finding.dependency_name,
                dependency_version=finding.dependency_version,
                ecosystem=finding.ecosystem,
                identifier=finding.identifier,
                aliases=finding.aliases,
                sources=[source.value for source in finding.sources],
                severity=finding.severity.value,
                cvss=finding.cvss,
                status=finding.status.value,
                summary=finding.summary,
                remediation=(
                    {
                        "rules": [
                            {
                                "introduced": rule.introduced,
                                "fixed": rule.fixed,
                                "affected_range": rule.affected_range,
                            }
                            for rule in finding.remediation.rules
                        ],
                    }
                    if finding.remediation is not None
                    else None
                ),
                fixed_versions=finding.fixed_versions,
                known_exploited=finding.known_exploited,
                kev_date_added=finding.kev_date_added,
                kev_vendor=finding.kev_vendor,
                kev_product=finding.kev_product,
                kev_required_action=finding.kev_required_action,
                kev_known_ransomware=finding.kev_known_ransomware,
                vulncheck_known_exploited=finding.vulncheck_known_exploited,
                vulncheck_date_added=finding.vulncheck_date_added,
                vulncheck_cisa_date_added=finding.vulncheck_cisa_date_added,
                vulncheck_due_date=finding.vulncheck_due_date,
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
            for finding in findings
        ]
        self.session.add_all(models)
        self.session.flush()

    def list_by_scan(
        self,
        scan_id: int,
    ) -> list[Finding]:

        return (
            self.session.query(Finding)
            .filter(
                Finding.scan_id == scan_id,
            )
            .all()
        )

    def get_all(self) -> list[Finding]:
        """
        Return all findings.
        """

        return (
            self.session.query(Finding)
            .order_by(
                Finding.id.desc(),
            )
            .all()
        )

    def count_by_scan(
        self,
        scan_id: int,
    ) -> int:

        return (
            self.session.query(Finding)
            .filter(
                Finding.scan_id == scan_id,
            )
            .count()
        )

    def count_by_severity(
        self,
    ) -> dict[str, int]:
        """
        Return findings grouped by severity.
        """

        findings = self.session.query(Finding).all()

        severity_counts = Counter(
            finding.severity.value for finding in findings
        )

        return dict(severity_counts)

    def count_by_repository(
        self,
        repository_id: int,
    ) -> int:
        """
        Return number of findings for a repository.
        """

        return (
            self.session.query(Finding)
            .join(
                Scan,
                Finding.scan_id == Scan.id,
            )
            .filter(
                Scan.repository_id == repository_id,
            )
            .count()
        )

    def count_by_repository_and_severity(
        self,
        repository_id: int,
    ) -> dict[str, int]:
        """
        Return findings grouped by severity for a repository.
        """

        findings = (
            self.session.query(Finding)
            .join(
                Scan,
                Finding.scan_id == Scan.id,
            )
            .filter(
                Scan.repository_id == repository_id,
            )
            .all()
        )

        return dict(Counter(finding.severity for finding in findings))
