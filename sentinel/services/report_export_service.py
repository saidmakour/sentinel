from __future__ import annotations

from pathlib import Path

from sentinel.config.settings import settings
from sentinel.log import get_logger
from sentinel.reports.registry import ReportRendererRegistry
from sentinel.services.scan_report_service import ScanReportService

logger = get_logger(__name__)


class ReportExportService:
    def __init__(
        self,
        scan_report_service: ScanReportService,
        renderer_registry: ReportRendererRegistry | None = None,
        report_path: str | None = None,
    ) -> None:
        self.scan_report_service = scan_report_service
        self.renderer_registry = renderer_registry or ReportRendererRegistry()
        self.report_path = Path(
            report_path or settings.report_path,
        )

    def export(
        self,
        scan_id: int,
        format: str,
        output_path: Path | None = None,
    ) -> Path:

        normalized_format = format.lower()

        logger.info(
            "Starting report export: scan_id=%s format=%s",
            scan_id,
            normalized_format,
        )

        report = self.scan_report_service.get_report(
            scan_id,
        )

        renderer = self.renderer_registry.create(
            normalized_format,
        )

        logger.debug(
            "Report renderer created: scan_id=%s format=%s renderer=%s",
            scan_id,
            normalized_format,
            type(renderer).__name__,
        )

        content = renderer.render(
            report,
        )

        destination = output_path or self._build_output_path(
            scan_id,
            normalized_format,
        )

        logger.debug(
            "Writing report: scan_id=%s destination=%s",
            scan_id,
            destination,
        )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        destination.write_text(
            content,
            encoding="utf-8",
        )

        logger.info(
            "Report export completed: scan_id=%s format=%s destination=%s",
            scan_id,
            normalized_format,
            destination,
        )

        return destination

    def _build_output_path(
        self,
        scan_id: int,
        format: str,
    ) -> Path:

        extension = format.lower()

        return self.report_path / f"scan-{scan_id}.{extension}"
