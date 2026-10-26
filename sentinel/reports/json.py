import json

from sentinel.dto.scan_report import ScanReport
from sentinel.reports.base import BaseReportRenderer
from sentinel.reports.formatters import format_datetime
from sentinel.reports.formatters import format_duration


class JsonReportRenderer(BaseReportRenderer):
    def render(
        self,
        report: ScanReport,
    ) -> str:
        data = {
            "scan": {
                "id": report.scan_id,
                "repository_id": report.repository_id,
                "profile": report.profile_name,
                "status": report.status.value,
                "security_status": report.security_status.value,
                "started_at": format_datetime(
                    report.started_at,
                ),
                "finished_at": format_datetime(
                    report.finished_at,
                ),
                "duration": format_duration(
                    report.duration_seconds,
                ),
                "error_message": report.error_message,
            },
            "source": {
                "type": report.source_type.value,
                "reference": report.source_reference,
                "branch": report.source_branch,
                "commit": report.source_commit,
            },
            "risk": {
                "score": report.risk_score,
                "severity": {
                    "critical": report.critical_count,
                    "high": report.high_count,
                    "medium": report.medium_count,
                    "low": report.low_count,
                },
            },
            "dependency_security": [
                {
                    "dependency": summary.dependency_name,
                    "version": summary.installed_version,
                    "ecosystem": summary.ecosystem.value,
                    "security_status": (summary.security_status.value),
                    "finding_count": summary.finding_count,
                    "open_finding_count": (summary.open_finding_count),
                    "recommended_version": (summary.recommended_version),
                }
                for summary in report.dependency_summaries
            ],
            "findings": [
                {
                    "dependency": finding.dependency_name,
                    "version": finding.dependency_version,
                    "ecosystem": finding.ecosystem.value,
                    "identifier": finding.identifier,
                    "aliases": finding.aliases,
                    "severity": finding.severity.value,
                    "status": finding.status.value,
                    "sources": [source.value for source in finding.sources],
                    "summary": finding.summary,
                    "cvss": finding.cvss,
                    "known_exploited": (finding.known_exploited),
                    "kev_date_added": (
                        finding.kev_date_added.isoformat()
                        if finding.kev_date_added
                        else None
                    ),
                    "kev_vendor": finding.kev_vendor,
                    "kev_product": finding.kev_product,
                    "kev_required_action": (finding.kev_required_action),
                    "kev_known_ransomware": (finding.kev_known_ransomware),
                    "vulncheck_known_exploited": (
                        finding.vulncheck_known_exploited
                    ),
                    "vulncheck_date_added": (
                        finding.vulncheck_date_added.isoformat()
                        if finding.vulncheck_date_added
                        else None
                    ),
                    "vulncheck_cisa_date_added": (
                        finding.vulncheck_cisa_date_added.isoformat()
                        if finding.vulncheck_cisa_date_added
                        else None
                    ),
                    "vulncheck_due_date": (
                        finding.vulncheck_due_date.isoformat()
                        if finding.vulncheck_due_date
                        else None
                    ),
                    "vulncheck_vendor": finding.vulncheck_vendor,
                    "vulncheck_product": finding.vulncheck_product,
                    "vulncheck_required_action": (
                        finding.vulncheck_required_action
                    ),
                    "vulncheck_known_ransomware": (
                        finding.vulncheck_known_ransomware
                    ),
                    "vulncheck_reported_exploited_by_canaries": (
                        finding.vulncheck_reported_exploited_by_canaries
                    ),
                    "epss_score": finding.epss_score,
                    "epss_percentile": (finding.epss_percentile),
                    "remediation": (
                        {
                            "rules": [
                                {
                                    "introduced": rule.introduced,
                                    "fixed": rule.fixed,
                                    "affected_range": (rule.affected_range),
                                }
                                for rule in finding.remediation.rules
                            ],
                        }
                        if finding.remediation
                        else None
                    ),
                    "fixed_versions": finding.fixed_versions,
                }
                for finding in report.findings
            ],
        }

        return json.dumps(
            data,
            indent=2,
        )
