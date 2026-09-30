from sqlalchemy.orm import Session

from sentinel.dto.dashboard_risk_summary import DashboardRiskSummary
from sentinel.dto.dashboard_summary import DashboardSummary
from sentinel.dto.repository_dashboard_summary import (
    RepositoryDashboardSummary,
)
from sentinel.dto.repository_risk_summary import RepositoryRiskSummary
from sentinel.enums.scan_status import ScanStatus
from sentinel.repositories.finding_repository import FindingRepository
from sentinel.repositories.repository_repository import RepositoryRepository
from sentinel.repositories.scan_repository import ScanRepository
from sentinel.services.risk_service import RiskService


class DashboardService:
    def __init__(
        self,
        session: Session,
    ) -> None:

        self.scan_repo = ScanRepository(
            session,
        )

        self.finding_repo = FindingRepository(
            session,
        )
        self.repository_repo = RepositoryRepository(
            session,
        )
        self.risk_service = RiskService()

    def summary(self) -> DashboardSummary:

        scans = self.scan_repo.get_all()

        findings = self.finding_repo.get_all()

        findings_by_severity = self.finding_repo.count_by_severity()

        completed = sum(scan.status == ScanStatus.SUCCESS for scan in scans)

        failed = sum(scan.status == ScanStatus.FAILED for scan in scans)

        return DashboardSummary(
            total_scans=len(scans),
            completed_scans=completed,
            failed_scans=failed,
            total_findings=len(findings),
            findings_by_severity=findings_by_severity,
        )

    def repository_summary(
        self,
        repository_id: int,
    ) -> RepositoryDashboardSummary:

        scans = self.scan_repo.list_by_repository(
            repository_id,
        )

        findings = self.finding_repo.count_by_repository(
            repository_id,
        )

        latest = scans[0] if scans else None

        return RepositoryDashboardSummary(
            repository_id=repository_id,
            total_scans=len(scans),
            total_findings=findings,
            last_scan_status=(latest.status if latest else None),
            last_scan_profile=(latest.profile_name if latest else None),
        )

    def risk_summary(
        self,
        repository_id: int,
        repository_name: str,
    ) -> RepositoryRiskSummary:

        counts = self.finding_repo.count_by_repository_and_severity(
            repository_id,
        )

        (
            critical,
            high,
            medium,
            low,
            score,
        ) = self.risk_service.calculate(
            counts,
        )

        return RepositoryRiskSummary(
            repository_id=repository_id,
            repository_name=repository_name,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            total_findings=sum(counts.values()),
            risk_score=score,
        )

    def risk_overview(
        self,
    ) -> list[RepositoryRiskSummary]:

        repositories = self.repository_repo.get_all()

        summaries: list[RepositoryRiskSummary] = []

        for repository in repositories:
            summaries.append(
                self.risk_summary(
                    repository.id,
                    repository.name,
                )
            )

        return sorted(
            summaries,
            key=lambda item: item.risk_score,
            reverse=True,
        )

    def global_risk_summary(
        self,
    ) -> DashboardRiskSummary:

        findings = self.finding_repo.get_all()

        counts: dict[str, int] = {}

        repositories: set[int] = set()

        for finding in findings:
            counts[finding.severity] = (
                counts.get(
                    finding.severity,
                    0,
                )
                + 1
            )

            if finding.scan:
                repositories.add(
                    finding.scan.repository_id,
                )

        (
            critical,
            high,
            medium,
            low,
            score,
        ) = self.risk_service.calculate(
            counts,
        )

        return DashboardRiskSummary(
            total_findings=len(findings),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            risk_score=score,
            repositories_at_risk=len(repositories),
        )
