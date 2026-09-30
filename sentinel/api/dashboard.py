from sqlalchemy.orm import Session

from sentinel.services.dashboard_service import DashboardService


class DashboardAPI:
    def __init__(
        self,
        session: Session,
    ) -> None:

        self.service = DashboardService(
            session,
        )

    def summary(self):

        return self.service.summary()

    def risk_overview(self):

        return self.service.risk_overview()

    def repository_summary(
        self,
        repository_id: int,
    ):

        return self.service.repository_summary(
            repository_id,
        )
