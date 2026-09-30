from sqlalchemy.orm import Session

from sentinel.dto.scan_comparison import ScanComparison
from sentinel.exceptions.scan import ScanNotFoundError
from sentinel.repositories.scan_repository import ScanRepository
from sentinel.services.scan_comparison_service import ScanComparisonService


class ScanHistoryService:
    """
    Handles scan history operations.
    """

    def __init__(
        self,
        session: Session,
    ) -> None:

        self.scan_repo = ScanRepository(
            session,
        )

        self.comparison_service = ScanComparisonService()

    def compare_with_previous(
        self,
        scan_id: int,
    ) -> ScanComparison | None:
        """
        Compare a scan with its previous scan.

        Returns None when there is no previous scan.
        """

        scan = self.scan_repo.get_by_id(
            scan_id,
        )

        if not scan:
            raise ScanNotFoundError(
                f"Scan '{scan_id}' not found",
            )

        previous = self.scan_repo.get_previous_scan(
            scan,
        )

        if not previous:
            return None

        return self.comparison_service.compare(
            previous,
            scan,
        )
