from sentinel.dto.scan_summary import ScanSummary
from sentinel.dto.severity_summary import SeveritySummary


def test_scan_summary_creation():
    severity = SeveritySummary(
        critical=1,
        high=2,
        medium=3,
        low=4,
        unknown=0,
    )

    summary = ScanSummary(
        scan_id=42,
        status="success",
        dependency_count=12,
        finding_count=6,
        duration_seconds=18,
        severity=severity,
        source_type="",
        source_reference="",
        vulnerability_status={},
    )

    assert summary.scan_id == 42
    assert summary.status == "success"
    assert summary.dependency_count == 12
    assert summary.finding_count == 6
    assert summary.duration_seconds == 18
    assert summary.severity is severity


def test_scan_summary_allows_none_duration():
    summary = ScanSummary(
        scan_id=1,
        status="started",
        dependency_count=0,
        finding_count=0,
        duration_seconds=None,
        severity=SeveritySummary(),
        source_type="",
        source_reference="",
        vulnerability_status={},
    )

    assert summary.duration_seconds is None
