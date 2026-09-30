from pathlib import Path
from unittest.mock import Mock

import pytest

from sentinel.dto.scan_report import ScanReport
from sentinel.renderers.registry import RendererRegistry
from sentinel.services.report_export_service import ReportExportService


@pytest.fixture
def scan_report_service() -> Mock:
    return Mock()


@pytest.fixture
def renderer_registry() -> Mock:
    return Mock(spec=RendererRegistry)


@pytest.fixture
def service(
    scan_report_service: Mock,
    renderer_registry: Mock,
    tmp_path: Path,
) -> ReportExportService:
    return ReportExportService(
        scan_report_service=scan_report_service,
        renderer_registry=renderer_registry,
        report_path=str(tmp_path),
    )


@pytest.fixture
def scan_report() -> Mock:
    return Mock(spec=ScanReport)


def test_export_creates_report_file(
    service: ReportExportService,
    scan_report_service: Mock,
    renderer_registry: Mock,
    scan_report: Mock,
    tmp_path: Path,
) -> None:
    renderer = Mock()
    renderer.render.return_value = '{"scan_id": 1}'

    scan_report_service.get_report.return_value = scan_report
    renderer_registry.create.return_value = renderer

    destination = service.export(
        scan_id=1,
        format="json",
    )

    assert destination == tmp_path / "scan-1.json"
    assert destination.exists()
    assert destination.read_text(encoding="utf-8") == ('{"scan_id": 1}')

    scan_report_service.get_report.assert_called_once_with(
        1,
    )

    renderer_registry.create.assert_called_once_with(
        "json",
    )

    renderer.render.assert_called_once_with(
        scan_report,
    )


def test_export_normalizes_format_to_lowercase(
    service: ReportExportService,
    scan_report_service: Mock,
    renderer_registry: Mock,
    scan_report: Mock,
) -> None:
    renderer = Mock()
    renderer.render.return_value = "{}"

    scan_report_service.get_report.return_value = scan_report
    renderer_registry.create.return_value = renderer

    destination = service.export(
        scan_id=1,
        format="JSON",
    )

    assert destination.name == "scan-1.json"

    renderer_registry.create.assert_called_once_with(
        "json",
    )


def test_export_uses_custom_output_path(
    service: ReportExportService,
    scan_report_service: Mock,
    renderer_registry: Mock,
    scan_report: Mock,
    tmp_path: Path,
) -> None:
    renderer = Mock()
    renderer.render.return_value = "{}"

    scan_report_service.get_report.return_value = scan_report
    renderer_registry.create.return_value = renderer

    output_path = tmp_path / "custom" / "my-report.json"

    destination = service.export(
        scan_id=1,
        format="json",
        output_path=output_path,
    )

    assert destination == output_path
    assert destination.exists()
    assert (
        destination.read_text(
            encoding="utf-8",
        )
        == "{}"
    )


def test_export_creates_parent_directory(
    service: ReportExportService,
    scan_report_service: Mock,
    renderer_registry: Mock,
    scan_report: Mock,
    tmp_path: Path,
) -> None:
    renderer = Mock()
    renderer.render.return_value = "{}"

    scan_report_service.get_report.return_value = scan_report
    renderer_registry.create.return_value = renderer

    output_path = tmp_path / "nested" / "reports" / "scan.json"

    destination = service.export(
        scan_id=1,
        format="json",
        output_path=output_path,
    )

    assert destination == output_path
    assert output_path.exists()


def test_export_propagates_report_service_error(
    service: ReportExportService,
    scan_report_service: Mock,
) -> None:
    scan_report_service.get_report.side_effect = ValueError(
        "Scan '999' not found",
    )

    with pytest.raises(
        ValueError,
        match="Scan '999' not found",
    ):
        service.export(
            scan_id=999,
            format="json",
        )


def test_export_propagates_renderer_registry_error(
    service: ReportExportService,
    scan_report_service: Mock,
    renderer_registry: Mock,
    scan_report: Mock,
) -> None:
    scan_report_service.get_report.return_value = scan_report

    renderer_registry.create.side_effect = ValueError(
        "Unsupported report format",
    )

    with pytest.raises(
        ValueError,
        match="Unsupported report format",
    ):
        service.export(
            scan_id=1,
            format="unsupported",
        )


@pytest.mark.parametrize(
    "format",
    [
        "json",
        "html",
        "markdown",
        "sarif",
    ],
)
def test_export_supports_report_format(
    service: ReportExportService,
    scan_report_service: Mock,
    renderer_registry: Mock,
    scan_report: Mock,
    format: str,
) -> None:
    renderer = Mock()
    renderer.render.return_value = "report content"

    scan_report_service.get_report.return_value = scan_report
    renderer_registry.create.return_value = renderer

    destination = service.export(
        scan_id=1,
        format=format,
    )

    assert destination.name == f"scan-1.{format}"

    renderer_registry.create.assert_called_once_with(
        format,
    )

    renderer.render.assert_called_once_with(
        scan_report,
    )
