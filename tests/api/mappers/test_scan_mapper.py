# tests/api/mappers/test_scan_summary.py

from datetime import datetime
from datetime import timedelta
from types import SimpleNamespace

from sentinel.api.mappers.scan_mapper import scan_to_summary_schema
from sentinel.api.schemas.scan import ScanSummarySchema
from sentinel.enums.scan_status import ScanStatus


def test_scan_to_summary_schema_maps_enum_status_and_duration() -> None:
    scan = SimpleNamespace(
        id=1,
        repository_id=123,
        profile_name="default",
        status=ScanStatus.SUCCESS,
        started_at=datetime(2026, 7, 25, 9, 0, 0),
        finished_at=datetime(2026, 7, 25, 9, 5, 0),
        duration=timedelta(minutes=5),
        dependency_count=42,
        findings=[object(), object(), object()],
    )

    result = scan_to_summary_schema(scan)

    assert result == ScanSummarySchema(
        id=1,
        repository_id=123,
        profile_name="default",
        status="success",
        started_at=datetime(2026, 7, 25, 9, 0, 0),
        finished_at=datetime(2026, 7, 25, 9, 5, 0),
        duration="0:05:00",
        dependency_count=42,
        finding_count=3,
    )


def test_scan_to_summary_schema_maps_string_status_and_none_duration() -> None:
    scan = SimpleNamespace(
        id=2,
        repository_id=456,
        profile_name="nightly",
        status=ScanStatus.FAILED,
        started_at=datetime(2026, 7, 25, 10, 0, 0),
        finished_at=None,
        duration=None,
        dependency_count=12,
        findings=[object()],
    )

    result = scan_to_summary_schema(scan)

    assert result == ScanSummarySchema(
        id=2,
        repository_id=456,
        profile_name="nightly",
        status="failed",
        started_at=datetime(2026, 7, 25, 10, 0, 0),
        finished_at=None,
        duration=None,
        dependency_count=12,
        finding_count=1,
    )
