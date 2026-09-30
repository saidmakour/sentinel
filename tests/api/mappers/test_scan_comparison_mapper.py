# tests/api/mappers/test_scan_comparison.py

from types import SimpleNamespace

from sentinel.api.mappers.scan_comparison_mapper import (
    scan_comparison_to_schema,
)
from sentinel.api.schemas.scan_comparison import FindingComparisonSchema
from sentinel.api.schemas.scan_comparison import ScanComparisonSchema
from sentinel.dto.scan_comparison import ScanComparison


def test_scan_comparison_to_schema_maps_empty_lists() -> None:
    comparison = ScanComparison(
        previous_scan_id=1,
        current_scan_id=2,
        added=[],
        resolved=[],
        unchanged=[],
    )

    assert scan_comparison_to_schema(comparison) == ScanComparisonSchema(
        previous_scan_id=1,
        current_scan_id=2,
        added=[],
        resolved=[],
        unchanged=[],
        added_count=0,
        resolved_count=0,
        unchanged_count=0,
    )


def test_scan_comparison_to_schema_maps_all_fields() -> None:
    added_finding = SimpleNamespace(
        dependency_name="requests",
        dependency_version="2.31.0",
        identifier="CVE-2026-0001",
        severity="high",
        summary="New vulnerability detected",
    )
    resolved_finding = SimpleNamespace(
        dependency_name="urllib3",
        dependency_version="1.26.18",
        identifier="CVE-2026-0002",
        severity="medium",
        summary="Previously known vulnerability resolved",
    )
    unchanged_finding = SimpleNamespace(
        dependency_name="jinja2",
        dependency_version="3.1.2",
        identifier="CVE-2026-0003",
        severity="low",
        summary="Vulnerability still present",
    )

    comparison = ScanComparison(
        previous_scan_id=1,
        current_scan_id=2,
        added=[added_finding],
        resolved=[resolved_finding],
        unchanged=[unchanged_finding],
    )

    result = scan_comparison_to_schema(comparison)

    assert result == ScanComparisonSchema(
        previous_scan_id=1,
        current_scan_id=2,
        added=[
            FindingComparisonSchema(
                dependency_name="requests",
                dependency_version="2.31.0",
                identifier="CVE-2026-0001",
                severity="high",
                summary="New vulnerability detected",
            ),
        ],
        resolved=[
            FindingComparisonSchema(
                dependency_name="urllib3",
                dependency_version="1.26.18",
                identifier="CVE-2026-0002",
                severity="medium",
                summary="Previously known vulnerability resolved",
            ),
        ],
        unchanged=[
            FindingComparisonSchema(
                dependency_name="jinja2",
                dependency_version="3.1.2",
                identifier="CVE-2026-0003",
                severity="low",
                summary="Vulnerability still present",
            ),
        ],
        added_count=1,
        resolved_count=1,
        unchanged_count=1,
    )
