from sentinel.api.schemas.scan_comparison import FindingComparisonSchema
from sentinel.api.schemas.scan_comparison import ScanComparisonSchema
from sentinel.dto.scan_comparison import ScanComparison


def scan_comparison_to_schema(
    comparison: ScanComparison,
) -> ScanComparisonSchema:

    return ScanComparisonSchema(
        previous_scan_id=comparison.previous_scan_id,
        current_scan_id=comparison.current_scan_id,
        added=[
            FindingComparisonSchema(
                dependency_name=finding.dependency_name,
                dependency_version=finding.dependency_version,
                identifier=finding.identifier,
                severity=finding.severity,
                summary=finding.summary,
            )
            for finding in comparison.added
        ],
        resolved=[
            FindingComparisonSchema(
                dependency_name=finding.dependency_name,
                dependency_version=finding.dependency_version,
                identifier=finding.identifier,
                severity=finding.severity,
                summary=finding.summary,
            )
            for finding in comparison.resolved
        ],
        unchanged=[
            FindingComparisonSchema(
                dependency_name=finding.dependency_name,
                dependency_version=finding.dependency_version,
                identifier=finding.identifier,
                severity=finding.severity,
                summary=finding.summary,
            )
            for finding in comparison.unchanged
        ],
        added_count=comparison.added_count,
        resolved_count=comparison.resolved_count,
        unchanged_count=comparison.unchanged_count,
    )
