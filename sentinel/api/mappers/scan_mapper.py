from sentinel.api.schemas.scan import ScanSummarySchema
from sentinel.models.scan import Scan


def scan_to_summary_schema(
    scan: Scan,
) -> ScanSummarySchema:

    return ScanSummarySchema(
        id=scan.id,
        repository_id=scan.repository_id,
        profile_name=scan.profile_name,
        status=(
            scan.status.value if hasattr(scan.status, "value") else scan.status
        ),
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        duration=(str(scan.duration) if scan.duration is not None else None),
        dependency_count=scan.dependency_count,
        finding_count=len(scan.findings),
    )
