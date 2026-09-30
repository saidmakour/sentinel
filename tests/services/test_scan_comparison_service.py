from unittest.mock import MagicMock

from sentinel.enums.severity import Severity
from sentinel.models.finding import Finding
from sentinel.models.scan import Scan
from sentinel.services.scan_comparison_service import ScanComparisonService


def create_scan(
    *,
    scan_id: int,
) -> Scan:
    return Scan(
        id=scan_id,
    )


def create_finding(
    *,
    identifier: str,
):
    finding = MagicMock()

    finding.comparison_key = identifier

    return finding


def test_scan_comparison_service_can_be_created() -> None:
    service = ScanComparisonService()

    assert service is not None


def test_compare_returns_empty_comparison_when_no_findings() -> None:
    service = ScanComparisonService()

    previous_scan = create_scan(
        scan_id=1,
    )

    current_scan = create_scan(
        scan_id=2,
    )

    result = service.compare(
        previous_scan,
        current_scan,
    )

    assert result.previous_scan_id == 1
    assert result.current_scan_id == 2

    assert result.added == []
    assert result.resolved == []
    assert result.unchanged == []


def test_compare_detects_added_finding() -> None:
    service = ScanComparisonService()

    previous_scan = create_scan(
        scan_id=1,
    )

    current_scan = create_scan(
        scan_id=2,
    )

    added_finding = create_finding(
        identifier="CVE-2026-0001",
    )

    current_scan.findings = [
        added_finding,
    ]

    result = service.compare(
        previous_scan,
        current_scan,
    )

    assert result.added == [
        added_finding,
    ]

    assert result.resolved == []
    assert result.unchanged == []


def test_compare_detects_resolved_finding() -> None:
    service = ScanComparisonService()

    previous_scan = create_scan(
        scan_id=1,
    )

    current_scan = create_scan(
        scan_id=2,
    )

    resolved_finding = create_finding(
        identifier="CVE-2026-0001",
    )

    previous_scan.findings = [
        resolved_finding,
    ]

    result = service.compare(
        previous_scan,
        current_scan,
    )

    assert result.added == []
    assert result.resolved == [
        resolved_finding,
    ]
    assert result.unchanged == []


def test_compare_detects_unchanged_finding() -> None:
    service = ScanComparisonService()

    previous_scan = create_scan(
        scan_id=1,
    )

    current_scan = create_scan(
        scan_id=2,
    )

    previous_finding = create_finding(
        identifier="CVE-2026-0001",
    )

    current_finding = create_finding(
        identifier="CVE-2026-0001",
    )

    previous_scan.findings = [
        previous_finding,
    ]

    current_scan.findings = [
        current_finding,
    ]

    result = service.compare(
        previous_scan,
        current_scan,
    )

    assert result.added == []
    assert result.resolved == []
    assert result.unchanged == [
        current_finding,
    ]


def test_compare_detects_added_resolved_and_unchanged_findings() -> None:
    service = ScanComparisonService()

    previous_scan = create_scan(
        scan_id=1,
    )

    current_scan = create_scan(
        scan_id=2,
    )

    resolved_finding = create_finding(
        identifier="CVE-2026-0001",
    )

    unchanged_previous = create_finding(
        identifier="CVE-2026-0002",
    )

    unchanged_current = create_finding(
        identifier="CVE-2026-0002",
    )

    added_finding = create_finding(
        identifier="CVE-2026-0003",
    )

    previous_scan.findings = [
        resolved_finding,
        unchanged_previous,
    ]

    current_scan.findings = [
        unchanged_current,
        added_finding,
    ]

    result = service.compare(
        previous_scan,
        current_scan,
    )

    assert result.added == [
        added_finding,
    ]

    assert result.resolved == [
        resolved_finding,
    ]

    assert result.unchanged == [
        unchanged_current,
    ]


def test_compare_uses_comparison_key() -> None:
    service = ScanComparisonService()

    previous_scan = create_scan(
        scan_id=1,
    )

    current_scan = create_scan(
        scan_id=2,
    )

    previous_finding = create_finding(
        identifier="CVE-2026-0001",
    )

    current_finding = create_finding(
        identifier="CVE-2026-0001",
    )

    previous_scan.findings = [
        previous_finding,
    ]

    current_scan.findings = [
        current_finding,
    ]

    result = service.compare(
        previous_scan,
        current_scan,
    )

    assert result.unchanged == [
        current_finding,
    ]

    assert result.added == []
    assert result.resolved == []


def create_finding_2(
    *,
    scan_id: int,
    identifier: str,
    dependency_name: str = "requests",
) -> Finding:
    return Finding(
        scan_id=scan_id,
        dependency_name=dependency_name,
        dependency_version="2.32.0",
        identifier=identifier,
        severity=Severity.HIGH,
        sources=["OSV"],
        summary="Test vulnerability",
    )


def test_compare_real_scan_findings() -> None:
    service = ScanComparisonService()

    previous_scan = Scan(
        id=1,
    )

    current_scan = Scan(
        id=2,
    )

    previous_scan.findings = [
        create_finding_2(
            scan_id=1,
            identifier="CVE-2026-0001",
        ),
        create_finding_2(
            scan_id=1,
            identifier="CVE-2026-0002",
        ),
    ]

    current_scan.findings = [
        create_finding_2(
            scan_id=2,
            identifier="CVE-2026-0002",
        ),
        create_finding_2(
            scan_id=2,
            identifier="CVE-2026-0003",
        ),
    ]

    result = service.compare(
        previous_scan,
        current_scan,
    )

    assert len(result.added) == 1
    assert result.added[0].identifier == "CVE-2026-0003"

    assert len(result.resolved) == 1
    assert result.resolved[0].identifier == "CVE-2026-0001"

    assert len(result.unchanged) == 1
    assert result.unchanged[0].identifier == "CVE-2026-0002"
