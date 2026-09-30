from sentinel.dto.scan_comparison import ScanComparison
from sentinel.models.scan import Scan


class ScanComparisonService:
    """
    Compare findings between two scans.
    """

    # TODO:
    # Compare VulnerabilityInfo instead of SQLAlchemy Finding once
    # all report and history services use FindingService.

    def compare(
        self,
        previous_scan: Scan,
        current_scan: Scan,
    ) -> ScanComparison:

        previous_findings = {
            finding.comparison_key: finding
            for finding in previous_scan.findings
        }

        current_findings = {
            finding.comparison_key: finding
            for finding in current_scan.findings
        }

        added = [
            finding
            for key, finding in current_findings.items()
            if key not in previous_findings
        ]

        resolved = [
            finding
            for key, finding in previous_findings.items()
            if key not in current_findings
        ]

        unchanged = [
            finding
            for key, finding in current_findings.items()
            if key in previous_findings
        ]

        return ScanComparison(
            previous_scan_id=previous_scan.id,
            current_scan_id=current_scan.id,
            added=added,
            resolved=resolved,
            unchanged=unchanged,
        )
