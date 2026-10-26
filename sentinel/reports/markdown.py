from sentinel.dto.scan_report import ScanReport
from sentinel.reports.base import BaseReportRenderer
from sentinel.reports.formatters import format_datetime
from sentinel.reports.formatters import format_duration


class MarkdownReportRenderer(BaseReportRenderer):
    def render(
        self,
        report: ScanReport,
    ) -> str:

        if not report.findings:
            return "# Sentinel Scan Report\n\nNo vulnerabilities found.\n"

        lines: list[str] = [
            "# Sentinel Vulnerability Report",
            "",
            "## Scan Information",
            "",
            f"- Scan ID: {report.scan_id}",
            f"- Repository ID: {report.repository_id}",
            f"- Profile: {report.profile_name}",
            f"- Engine Version: {report.engine_version}",
            f"- Status: {report.status.value}",
            f"- Started: {format_datetime(report.started_at)}",
            f"- Finished: {format_datetime(report.finished_at)}",
            f"- Duration: {format_duration(report.duration_seconds)}",
            "",
        ]

        lines.extend(
            [
                "## Source",
                "",
                f"- Type: {report.source_type.value}",
                f"- Référence: {report.source_reference}",
                f"- Branch: {report.source_branch}",
                f"- Commit: {report.source_commit}",
                f"- Error: {(str(report.error_message).strip() or 'N/A')}",
            ]
        )

        lines.extend(
            [
                "## Executive Summary",
                "",
                f"- Security Status: {report.security_status.value}",
                f"- Risk Score: {report.risk_score}",
                f"- Critical Findings: {report.critical_count}",
                f"- High Findings: {report.high_count}",
                f"- Medium Findings: {report.medium_count}",
                f"- Low Findings: {report.low_count}",
                (f"- Total Findings: {len(report.findings)}"),
                "",
            ]
        )

        lines.extend(
            self._render_dependency_security(
                report,
            )
        )
        lines.extend(
            self._render_findings_table(
                report,
            )
        )

        lines.extend(
            self._render_remediation_section(
                report,
            )
        )

        lines.extend(
            self._render_recommended_actions(
                report,
            )
        )
        lines.extend(
            self._render_kev_section(
                report,
            )
        )
        lines.extend(
            self._render_vulncheck_kev_section(
                report,
            )
        )
        lines.extend(
            self._render_recommendations(
                report,
            )
        )
        return "\n".join(lines)

    def _render_findings_table(
        self,
        report: ScanReport,
    ) -> list[str]:

        if not report.findings:
            return [
                "## Vulnerabilities",
                "",
                "No vulnerabilities found.",
                "",
            ]

        lines: list[str] = [
            "## Vulnerabilities",
            "",
            (
                "| Dependency | Version | Identifier | Severity | "
                "Status | CVSS | KEV | EPSS | Sources |"
            ),
            (
                "|------------|---------|------------|----------|"
                "----------|------|-----|------|---------|"
            ),
        ]

        for finding in report.findings:
            epss = (
                str(finding.epss_score)
                if finding.epss_score is not None
                else "N/A"
            )

            kev = "Yes" if finding.known_exploited else "No"

            sources = ", ".join(source.value for source in finding.sources)

            lines.append(
                f"| {finding.dependency_name} "
                f"| {finding.dependency_version} "
                f"| {finding.identifier} "
                f"| {finding.severity} "
                f"| {finding.status} "
                f"| {finding.cvss} "
                f"| {kev} "
                f"| {epss} "
                f"| {sources} |"
            )

        lines.append("")

        return lines

    def _render_kev_section(
        self,
        report: ScanReport,
    ) -> list[str]:

        kev_findings = [
            finding for finding in report.findings if finding.known_exploited
        ]

        if not kev_findings:
            return []

        lines: list[str] = [
            "## Known Exploited Vulnerabilities",
            "",
            (
                "| Dependency | CVE | Vendor | Product | "
                "Added Date | Ransomware |"
            ),
            (
                "|------------|-----|--------|---------|"
                "------------|------------|"
            ),
        ]

        for finding in kev_findings:
            added_date = (
                str(finding.kev_date_added)
                if finding.kev_date_added is not None
                else "N/A"
            )

            ransomware = (
                finding.kev_known_ransomware
                if finding.kev_known_ransomware is not None
                else "N/A"
            )

            vendor = (
                finding.kev_vendor if finding.kev_vendor is not None else "N/A"
            )

            product = (
                finding.kev_product
                if finding.kev_product is not None
                else "N/A"
            )

            lines.append(
                f"| {finding.dependency_name} "
                f"| {finding.identifier} "
                f"| {vendor} "
                f"| {product} "
                f"| {added_date} "
                f"| {ransomware} |"
            )

        lines.append("")

        return lines

    def _render_vulncheck_kev_section(
        self,
        report: ScanReport,
    ) -> list[str]:

        vulncheck_findings = [
            finding
            for finding in report.findings
            if finding.vulncheck_known_exploited
        ]

        if not vulncheck_findings:
            return []

        lines: list[str] = [
            "## VulnCheck Known Exploited Vulnerabilities",
            "",
            (
                "| Dependency | CVE | Vendor | Product | "
                "Added Date | CISA Added Date | Due Date | "
                "Ransomware | Canaries |"
            ),
            (
                "|------------|-----|--------|---------|"
                "------------|-----------------|----------|"
                "------------|----------|"
            ),
        ]

        for finding in vulncheck_findings:
            date_added = (
                str(finding.vulncheck_date_added)
                if finding.vulncheck_date_added is not None
                else "N/A"
            )

            cisa_date_added = (
                str(finding.vulncheck_cisa_date_added)
                if finding.vulncheck_cisa_date_added is not None
                else "N/A"
            )

            due_date = (
                str(finding.vulncheck_due_date)
                if finding.vulncheck_due_date is not None
                else "N/A"
            )

            vendor = (
                finding.vulncheck_vendor
                if finding.vulncheck_vendor is not None
                else "N/A"
            )

            product = (
                finding.vulncheck_product
                if finding.vulncheck_product is not None
                else "N/A"
            )

            ransomware = (
                finding.vulncheck_known_ransomware
                if finding.vulncheck_known_ransomware is not None
                else "N/A"
            )

            canaries = (
                "Yes"
                if finding.vulncheck_reported_exploited_by_canaries
                else "No"
            )

            lines.append(
                f"| {finding.dependency_name} "
                f"| {finding.identifier} "
                f"| {vendor} "
                f"| {product} "
                f"| {date_added} "
                f"| {cisa_date_added} "
                f"| {due_date} "
                f"| {ransomware} "
                f"| {canaries} |"
            )

        lines.append("")

        return lines

    def _render_recommendations(
        self,
        report: ScanReport,
    ) -> list[str]:

        recommendations: list[str] = []

        if report.critical_count > 0:
            recommendations.append(
                "Remediate critical vulnerabilities immediately."
            )

        if report.high_count > 0:
            recommendations.append(
                "Prioritize remediation of high severity vulnerabilities."
            )

        if any(finding.known_exploited for finding in report.findings):
            recommendations.append(
                "Prioritize vulnerabilities marked as known exploited."
            )

        if any(
            finding.epss_score is not None and finding.epss_score >= 0.5
            for finding in report.findings
        ):
            recommendations.append(
                "Review vulnerabilities with high EPSS scores."
            )

        if not recommendations:
            recommendations.append(
                "No immediate remediation actions required."
            )

        lines: list[str] = [
            "## Recommendations",
            "",
        ]

        for recommendation in recommendations:
            lines.append(f"- {recommendation}")

        lines.append("")

        return lines

    def _render_remediation_section(
        self,
        report: ScanReport,
    ) -> list[str]:

        remediation_findings = [
            finding
            for finding in report.findings
            if finding.remediation is not None or finding.fixed_versions
        ]

        if not remediation_findings:
            return []

        lines: list[str] = [
            "## Remediation",
            "",
        ]

        for finding in remediation_findings:
            lines.extend(
                [
                    f"### {finding.dependency_name} ({finding.identifier})",
                    "",
                ]
            )

            if finding.fixed_versions:
                fixed_versions = ", ".join(
                    f"`{version}`" for version in finding.fixed_versions
                )

                lines.append(f"- Fixed versions: {fixed_versions}")

            if finding.remediation is not None:
                lines.append("- Affected ranges:")

                for rule in finding.remediation.rules:
                    affected_range = (
                        rule.affected_range
                        if rule.affected_range is not None
                        else "N/A"
                    )

                    fixed = rule.fixed if rule.fixed is not None else "N/A"

                    lines.append(
                        f"  - `{affected_range}` → fixed in `{fixed}`"
                    )

            lines.append("")

        return lines

    def _render_dependency_security(
        self,
        report: ScanReport,
    ) -> list[str]:

        if not report.dependency_summaries:
            return [
                "## Dependency Security",
                "",
                "No dependency security information available.",
                "",
            ]

        lines: list[str] = [
            "## Dependency Security",
            "",
            (
                "| Dependency | Installed | Ecosystem | "
                "Security Status | Findings | Open | Recommended |"
            ),
            (
                "|------------|-----------|-----------|"
                "-----------------|----------|------|-------------|"
            ),
        ]

        for summary in report.dependency_summaries:
            recommended_version = (
                f"`{summary.recommended_version}`"
                if summary.recommended_version is not None
                else "N/A"
            )

            lines.append(
                f"| {summary.dependency_name} "
                f"| {summary.installed_version} "
                f"| {summary.ecosystem.value} "
                f"| {summary.security_status} "
                f"| {summary.finding_count} "
                f"| {summary.open_finding_count} "
                f"| {recommended_version} |"
            )

        lines.append("")

        return lines

    def _render_recommended_actions(
        self,
        report: ScanReport,
    ) -> list[str]:

        actions: list[str] = []

        for summary in report.dependency_summaries:
            if summary.recommended_version is None:
                continue

            if summary.security_status.value != "at_risk":
                continue

            actions.append(
                f"Upgrade {summary.dependency_name} "
                f"from `{summary.installed_version}` "
                f"to `{summary.recommended_version}`."
            )

        if not actions:
            return []

        lines: list[str] = [
            "## Recommended Actions",
            "",
        ]

        for action in actions:
            lines.append(f"- {action}")

        lines.append("")

        return lines
