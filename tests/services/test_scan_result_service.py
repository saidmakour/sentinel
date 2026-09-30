from unittest.mock import MagicMock

from sentinel.builders.scan_result_builder import ScanResultBuilder
from sentinel.dto.scan_result import ScanResult
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.services.scan_result_service import ScanResultService


def _dependency() -> ScannedDependency:
    return ScannedDependency(
        name="requests",
        version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
        priority=10,
    )


def _finding() -> VulnerabilityInfo:
    return VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-0001",
        aliases=["CVE-2026-0001"],
        sources=[Provider.OSV],
        summary="Test vulnerability",
        severity=Severity.HIGH,
        cvss=7.5,
    )


def test_scan_result_service_can_be_created() -> None:
    session = MagicMock()

    service = ScanResultService(session)

    assert service is not None
    assert service.dependency_repository is not None
    assert service.finding_service is not None
    assert service.builder is not None


def test_get_result_returns_scan_result() -> None:
    session = MagicMock()

    service = ScanResultService(session)

    service.dependency_repository.list_by_scan = MagicMock(
        return_value=[
            _dependency(),
        ],
    )

    service.finding_service.list_by_scan = MagicMock(
        return_value=[
            _finding(),
        ],
    )

    result = service.get_result(
        scan_id=1,
    )

    assert isinstance(result, ScanResult)


def test_get_result_loads_dependencies_for_scan() -> None:
    session = MagicMock()

    service = ScanResultService(session)

    service.dependency_repository.list_by_scan = MagicMock(
        return_value=[
            _dependency(),
        ],
    )

    service.finding_service.list_by_scan = MagicMock(
        return_value=[],
    )

    service.get_result(
        scan_id=42,
    )

    service.dependency_repository.list_by_scan.assert_called_once_with(
        42,
    )


def test_get_result_loads_findings_for_scan() -> None:
    session = MagicMock()

    service = ScanResultService(session)

    service.dependency_repository.list_by_scan = MagicMock(
        return_value=[],
    )

    service.finding_service.list_by_scan = MagicMock(
        return_value=[
            _finding(),
        ],
    )

    service.get_result(
        scan_id=42,
    )

    service.finding_service.list_by_scan.assert_called_once_with(
        42,
    )


def test_get_result_builds_result_from_dependencies_and_findings() -> None:
    session = MagicMock()

    service = ScanResultService(session)

    dependencies = [
        _dependency(),
    ]

    findings = [
        _finding(),
    ]

    service.dependency_repository.list_by_scan = MagicMock(
        return_value=dependencies,
    )

    service.finding_service.list_by_scan = MagicMock(
        return_value=findings,
    )

    builder = MagicMock(
        spec=ScanResultBuilder,
    )

    expected_result = MagicMock(
        spec=ScanResult,
    )

    builder.build.return_value = expected_result

    service.builder = builder

    result = service.get_result(
        scan_id=42,
    )

    builder.build.assert_called_once_with(
        dependencies,
        findings,
    )

    assert result is expected_result


def test_get_result_with_no_dependencies_and_no_findings() -> None:
    session = MagicMock()

    service = ScanResultService(session)

    service.dependency_repository.list_by_scan = MagicMock(
        return_value=[],
    )

    service.finding_service.list_by_scan = MagicMock(
        return_value=[],
    )

    result = service.get_result(
        scan_id=42,
    )

    assert result.dependencies == []
    assert result.findings == []
    assert result.statistics.dependency_count == 0
    assert result.statistics.finding_count == 0
