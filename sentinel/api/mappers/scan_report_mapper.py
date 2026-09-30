from sentinel.api.mappers.vulnerability_mapper import vulnerability_to_schema
from sentinel.api.schemas.scan_report import ScanReportSchema
from sentinel.dto.scan_report import ScanReport


def scan_report_to_schema(
    report: ScanReport,
) -> ScanReportSchema:
    return ScanReportSchema(
        scan_id=report.scan_id,
        repository_id=report.repository_id,
        profile_name=report.profile_name,
        engine_version=report.engine_version,
        status=report.status,
        security_status=report.security_status,
        started_at=report.started_at,
        finished_at=report.finished_at,
        duration_seconds=report.duration_seconds,
        source_type=report.source_type,
        source_reference=report.source_reference,
        source_branch=report.source_branch,
        source_commit=report.source_commit,
        findings=[
            vulnerability_to_schema(
                finding,
            )
            for finding in report.findings
        ],
        critical_count=report.critical_count,
        high_count=report.high_count,
        medium_count=report.medium_count,
        low_count=report.low_count,
        risk_score=report.risk_score,
        error_message=report.error_message,
    )
