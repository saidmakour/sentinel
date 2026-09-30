from sqlalchemy.orm import Session

from sentinel.dto.scan_report import ScanReport
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.exceptions.scan import ScanNotFoundError
from sentinel.log import get_logger
from sentinel.repositories.scan_repository import ScanRepository
from sentinel.services.dependency_security_service import (
    DependencySecurityService,
)
from sentinel.services.findings_service import FindingService
from sentinel.services.risk_service import RiskService
from sentinel.services.security_status_service import SecurityStatusService

logger = get_logger(__name__)


class ScanReportService:
    def __init__(
        self,
        session: Session,
    ) -> None:

        self.scan_repo = ScanRepository(
            session,
        )
        self.finding_service = FindingService(
            session,
        )
        self.risk_service = RiskService()
        self.security_status_service = SecurityStatusService()
        self.dependency_security_service = DependencySecurityService()

    def get_report(
        self,
        scan_id: int,
    ) -> ScanReport:

        scan = self.scan_repo.get_by_id(
            scan_id,
        )

        if not scan:
            raise ScanNotFoundError(
                f"Scan '{scan_id}' not found",
            )

        findings = self.finding_service.list_by_scan(
            scan_id,
        )

        severity_counts: dict[str, int] = {}

        for finding in findings:
            if finding.status != VulnerabilityStatus.OPEN:
                continue

            severity = finding.severity.value
            severity_counts[severity] = (
                severity_counts.get(
                    severity,
                    0,
                )
                + 1
            )

        open_severity_counts: dict[str, int] = {}

        for finding in findings:
            if finding.status != VulnerabilityStatus.OPEN:
                continue

            severity = finding.severity.value
            open_severity_counts[severity] = (
                open_severity_counts.get(severity, 0) + 1
            )

        critical, high, medium, low, score = self.risk_service.calculate(
            severity_counts,
        )

        security_status = self.security_status_service.calculate(
            findings,
        )

        dependency_summaries = self.dependency_security_service.summarize(
            findings,
        )

        return ScanReport(
            scan_id=scan.id,
            repository_id=scan.repository_id,
            profile_name=scan.profile_name,
            engine_version=scan.engine_version,
            status=scan.status,
            security_status=security_status,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            duration_seconds=scan.duration_seconds,
            source_type=scan.source_type,
            source_reference=scan.source_reference,
            source_branch=scan.source_branch,
            source_commit=scan.source_commit,
            findings=findings,
            dependency_summaries=dependency_summaries,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            risk_score=score,
            error_message=scan.error_message,
        )
