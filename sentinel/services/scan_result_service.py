from sqlalchemy.orm import Session

from sentinel.builders.scan_result_builder import ScanResultBuilder
from sentinel.dto.scan_result import ScanResult
from sentinel.repositories.dependency_repository import DependencyRepository
from sentinel.services.findings_service import FindingService


class ScanResultService:
    def __init__(
        self,
        session: Session,
    ) -> None:
        self.session = session

        self.dependency_repository = DependencyRepository(
            session,
        )

        self.finding_service = FindingService(
            session,
        )

        self.builder = ScanResultBuilder()

    def get_result(
        self,
        scan_id: int,
    ) -> ScanResult:

        dependencies = self.dependency_repository.list_by_scan(
            scan_id,
        )

        findings = self.finding_service.list_by_scan(
            scan_id,
        )

        return self.builder.build(
            dependencies,
            findings,
        )
