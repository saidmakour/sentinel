import json
from typing import Any

from sentinel.dto.scan_report import ScanReport
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.reports.base import BaseReportRenderer


class SarifReportRenderer(BaseReportRenderer):
    def render(
        self,
        report: ScanReport,
    ) -> str:
        rules_by_id: dict[str, dict[str, object]] = {}
        results: list[dict[str, object]] = []

        for finding in report.findings:
            rule_id = finding.identifier

            if rule_id not in rules_by_id:
                rules_by_id[rule_id] = self._build_rule(
                    finding,
                )

            results.append(
                self._build_result(
                    finding,
                )
            )

        sarif = {
            "version": "2.1.0",
            "$schema": ("https://json.schemastore.org/sarif-2.1.0.json"),
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Sentinel",
                            "version": report.engine_version,
                            "informationUri": (
                                "https://github.com/sentinel-project/sentinel"
                            ),
                            "rules": list(
                                rules_by_id.values(),
                            ),
                        }
                    },
                    "properties": {
                        "scan_id": report.scan_id,
                        "repository_id": report.repository_id,
                        "profile": report.profile_name,
                        "status": report.status.value,
                        "security_status": report.security_status.value,
                        "source_type": report.source_type.value,
                        "source_reference": report.source_reference,
                        "source_branch": report.source_branch,
                        "source_commit": report.source_commit,
                        "risk_score": report.risk_score,
                        "critical_count": report.critical_count,
                        "high_count": report.high_count,
                        "medium_count": report.medium_count,
                        "low_count": report.low_count,
                        "dependency_security": [
                            {
                                "dependency": summary.dependency_name,
                                "version": summary.installed_version,
                                "ecosystem": summary.ecosystem.value,
                                "security_status": summary.security_status.value,
                                "finding_count": summary.finding_count,
                                "open_finding_count": summary.open_finding_count,
                                "recommended_version": summary.recommended_version,
                            }
                            for summary in report.dependency_summaries
                        ],
                        "recommended_actions": [
                            (
                                f"Upgrade {summary.dependency_name} "
                                f"from {summary.installed_version} "
                                f"to {summary.recommended_version}."
                            )
                            for summary in report.dependency_summaries
                            if summary.recommended_version is not None
                        ],
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(
            sarif,
            indent=2,
        )

    @staticmethod
    def _build_rule(
        finding: VulnerabilityInfo,
    ) -> dict[str, Any]:
        rule: dict[str, Any] = {
            "id": finding.identifier,
            "name": finding.identifier,
            "shortDescription": {
                "text": finding.summary,
            },
            "properties": {
                "aliases": finding.aliases,
                "dependency": finding.dependency_name,
                "ecosystem": finding.ecosystem.value,
                "sources": [source.value for source in finding.sources],
                "known_exploited": (finding.known_exploited),
                "epss_score": finding.epss_score,
                "epss_percentile": (finding.epss_percentile),
            },
        }

        if finding.cvss is not None:
            rule["properties"]["cvss"] = finding.cvss

            rule["properties"]["security-severity"] = str(finding.cvss)

        if finding.remediation is not None:
            rule["help"] = {
                "text": ("Upgrade to a fixed version."),
            }

        return rule

    @staticmethod
    def _build_result(
        finding: VulnerabilityInfo,
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "ruleId": finding.identifier,
            "level": SarifReportRenderer._severity_level(
                finding.severity.value,
            ),
            "message": {
                "text": finding.summary,
            },
            "properties": (
                SarifReportRenderer._finding_properties(
                    finding,
                )
            ),
        }

        return result

    @staticmethod
    def _finding_properties(
        finding: VulnerabilityInfo,
    ) -> dict[str, object]:
        return {
            "dependency": finding.dependency_name,
            "version": finding.dependency_version,
            "ecosystem": finding.ecosystem.value,
            "identifier": finding.identifier,
            "aliases": finding.aliases,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "cvss": finding.cvss,
            "fixed_versions": finding.fixed_versions,
            "remediation": (
                [
                    {
                        "introduced": rule.introduced,
                        "fixed": rule.fixed,
                        "affected_range": (rule.affected_range),
                    }
                    for rule in finding.remediation.rules
                ]
                if finding.remediation is not None
                else []
            ),
            "known_exploited": (finding.known_exploited),
            "kev_date_added": (
                finding.kev_date_added.isoformat()
                if finding.kev_date_added is not None
                else None
            ),
            "kev_vendor": finding.kev_vendor,
            "kev_product": finding.kev_product,
            "kev_required_action": (finding.kev_required_action),
            "kev_known_ransomware": (finding.kev_known_ransomware),
            "vulncheck_known_exploited": (finding.vulncheck_known_exploited),
            "vulncheck_date_added": (
                finding.vulncheck_date_added.isoformat()
                if finding.vulncheck_date_added is not None
                else None
            ),
            "vulncheck_cisa_date_added": (
                finding.vulncheck_cisa_date_added.isoformat()
                if finding.vulncheck_cisa_date_added is not None
                else None
            ),
            "vulncheck_due_date": (
                finding.vulncheck_due_date.isoformat()
                if finding.vulncheck_due_date is not None
                else None
            ),
            "vulncheck_vendor": finding.vulncheck_vendor,
            "vulncheck_product": finding.vulncheck_product,
            "vulncheck_required_action": (finding.vulncheck_required_action),
            "vulncheck_known_ransomware": (finding.vulncheck_known_ransomware),
            "vulncheck_reported_exploited_by_canaries": (
                finding.vulncheck_reported_exploited_by_canaries
            ),
            "epss_score": finding.epss_score,
            "epss_percentile": (finding.epss_percentile),
            "sources": [source.value for source in finding.sources],
        }

    @staticmethod
    def _severity_level(
        severity: str,
    ) -> str:
        match severity.upper():
            case "CRITICAL" | "HIGH":
                return "error"

            case "MEDIUM":
                return "warning"

            case "LOW":
                return "note"

            case _:
                return "none"
