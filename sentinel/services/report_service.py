from collections import Counter

from sqlalchemy import func
from sqlalchemy.orm import Session

from sentinel.dto.scan_summary import ScanSummary
from sentinel.dto.severity_summary import SeveritySummary
from sentinel.enums.severity import Severity
from sentinel.exceptions.scan import NoScansFoundError
from sentinel.exceptions.scan import ScanNotFoundError
from sentinel.log import get_logger
from sentinel.models.dependency import Dependency
from sentinel.models.finding import Finding
from sentinel.models.scan import Scan

logger = get_logger(__name__)


class ReportService:
    def __init__(
        self,
        session: Session,
    ) -> None:
        self.session = session

    def get_scan_summary(
        self,
        scan_id: int,
    ) -> ScanSummary:

        logger.debug(
            "Building scan summary: scan_id=%s",
            scan_id,
        )

        scan = self.session.get(
            Scan,
            scan_id,
        )

        if scan is None:
            logger.debug(
                "Scan not found: scan_id=%s",
                scan_id,
            )

            raise ScanNotFoundError(
                f"Scan '{scan_id}' not found",
            )

        dependency_count = (
            self.session.query(
                func.count(Dependency.id),
            )
            .filter(
                Dependency.scan_id == scan_id,
            )
            .scalar()
        )

        findings = (
            self.session.query(
                Finding,
            )
            .filter(
                Finding.scan_id == scan_id,
            )
            .all()
        )

        severity = SeveritySummary()

        for finding in findings:
            try:
                level = Severity(
                    finding.severity.upper(),
                )
            except ValueError:
                level = Severity.UNKNOWN

            match level:
                case Severity.CRITICAL:
                    severity.critical += 1
                case Severity.HIGH:
                    severity.high += 1
                case Severity.MEDIUM:
                    severity.medium += 1
                case Severity.LOW:
                    severity.low += 1
                case Severity.UNKNOWN:
                    severity.unknown += 1

        vulnerability_status = Counter(
            finding.status.value for finding in findings
        )

        logger.debug(
            "Scan summary built: scan_id=%s dependencies=%s findings=%s",
            scan_id,
            dependency_count,
            len(findings),
        )

        return ScanSummary(
            scan_id=scan.id,
            status=scan.status,
            source_type=scan.source_type,
            source_reference=scan.source_reference,
            dependency_count=dependency_count,
            finding_count=len(findings),
            duration_seconds=scan.duration_seconds,
            severity=severity,
            vulnerability_status=dict(vulnerability_status),
        )

    def get_latest_summary(
        self,
    ) -> ScanSummary:

        logger.debug(
            "Retrieving latest scan summary",
        )

        latest_scan = (
            self.session.query(
                Scan,
            )
            .order_by(
                Scan.started_at.desc(),
            )
            .first()
        )

        if latest_scan is None:
            logger.debug(
                "No scans found while retrieving latest summary",
            )

            raise NoScansFoundError(
                "No scans found",
            )

        logger.debug(
            "Latest scan found: scan_id=%s",
            latest_scan.id,
        )

        return self.get_scan_summary(
            latest_scan.id,
        )

    def get_history(
        self,
        limit: int = 20,
    ) -> list[ScanSummary]:

        logger.debug(
            "Retrieving scan history: limit=%s",
            limit,
        )

        scans = (
            self.session.query(
                Scan,
            )
            .order_by(
                Scan.started_at.desc(),
            )
            .limit(
                limit,
            )
            .all()
        )

        summaries = [
            self.get_scan_summary(
                scan.id,
            )
            for scan in scans
        ]

        logger.debug(
            "Scan history retrieved: count=%s",
            len(summaries),
        )

        return summaries
