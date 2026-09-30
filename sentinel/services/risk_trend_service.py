from sqlalchemy.orm import Session

from sentinel.dto.risk_trend import RiskTrend
from sentinel.services.risk_history_service import RiskHistoryService


class RiskTrendService:
    """
    Calculates risk evolution between scans.
    """

    def __init__(
        self,
        session: Session,
    ) -> None:

        self.history_service = RiskHistoryService(
            session,
        )

    def get_trend(
        self,
        repository_id: int,
    ) -> RiskTrend:

        history = self.history_service.get_history(
            repository_id,
        )

        if not history:
            return RiskTrend(
                current_score=0,
                previous_score=None,
                delta=0,
                trend="unknown",
            )

        current = history[-1]

        previous = history[-2] if len(history) > 1 else None

        previous_score = previous.risk_score if previous else None

        delta = (
            current.risk_score - previous_score
            if previous_score is not None
            else 0
        )

        if previous_score is None:
            trend = "unknown"

        elif delta < 0:
            trend = "improving"

        elif delta > 0:
            trend = "degrading"

        else:
            trend = "stable"

        return RiskTrend(
            current_score=current.risk_score,
            previous_score=previous_score,
            delta=delta,
            trend=trend,
        )
