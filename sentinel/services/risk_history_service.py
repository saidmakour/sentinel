from sqlalchemy.orm import Session

from sentinel.dto.risk_history import RiskHistoryPoint
from sentinel.repositories.scan_repository import ScanRepository
from sentinel.services.risk_service import RiskService


class RiskHistoryService:
    """
    Builds risk evolution history for repositories.
    """

    def __init__(
        self,
        session: Session,
    ) -> None:

        self.scan_repo = ScanRepository(
            session,
        )

        self.risk_service = RiskService()

    def get_history(
        self,
        repository_id: int,
    ) -> list[RiskHistoryPoint]:

        scans = self.scan_repo.list_by_repository(
            repository_id,
        )

        history: list[RiskHistoryPoint] = []

        for scan in reversed(scans):
            counts: dict[str, int] = {}

            for finding in scan.findings:
                counts[finding.severity] = (
                    counts.get(
                        finding.severity,
                        0,
                    )
                    + 1
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

            history.append(
                RiskHistoryPoint(
                    scan_id=scan.id,
                    date=scan.started_at,
                    critical=critical,
                    high=high,
                    medium=medium,
                    low=low,
                    risk_score=score,
                )
            )

        return history
