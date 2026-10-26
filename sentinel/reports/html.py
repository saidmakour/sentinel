from html import escape

from sentinel.dto.scan_report import ScanReport
from sentinel.enums.security_status import SecurityStatus
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.reports.base import BaseReportRenderer
from sentinel.reports.formatters import format_datetime
from sentinel.reports.formatters import format_duration


class HtmlReportRenderer(BaseReportRenderer):
    """Render a ScanReport as a styled HTML security report."""

    def render(
        self,
        report: ScanReport,
    ) -> str:
        findings_rows = self._render_findings(report)
        dependency_security_section = self._render_dependency_security_section(
            report
        )
        recommendations_section = self._render_recommendations(report)
        remediation_section = self._render_remediation_section(report)
        kev_section = self._render_kev_section(report)
        vulncheck_kev_section = self._render_vulncheck_kev_section(report)

        source_reference = (
            escape(report.source_reference)
            if report.source_reference
            else "N/A"
        )

        source_branch = (
            escape(report.source_branch) if report.source_branch else "N/A"
        )

        source_commit = (
            escape(report.source_commit) if report.source_commit else "N/A"
        )

        error_section = self._render_error(report)

        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Sentinel Vulnerability Report</title>

<style>

:root {{
    --bg: #f4f6f8;
    --surface: #ffffff;
    --surface-alt: #f8fafc;
    --border: #e2e8f0;
    --text: #1e293b;
    --muted: #64748b;

    --critical: #b91c1c;
    --critical-bg: #fee2e2;

    --high: #c2410c;
    --high-bg: #ffedd5;

    --medium: #b45309;
    --medium-bg: #fef3c7;

    --low: #15803d;
    --low-bg: #dcfce7;

    --unknown: #475569;
    --unknown-bg: #e2e8f0;

    --open: #dc2626;
    --open-bg: #fee2e2;

    --resolved: #15803d;
    --resolved-bg: #dcfce7;

    --secure: #15803d;
    --secure-bg: #dcfce7;

    --at-risk: #c2410c;
    --at-risk-bg: #ffedd5;

    --status-critical: #b91c1c;
    --status-critical-bg: #fee2e2;

    --status-unknown: #475569;
    --status-unknown-bg: #e2e8f0;

    --shadow:
        0 4px 12px rgba(15, 23, 42, 0.06);
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
    line-height: 1.5;
}}

.container {{
    width: min(1500px, calc(100% - 48px));
    margin: 0 auto;
}}

.header {{
    background: #0f172a;
    color: white;
    padding: 32px 0;
    margin-bottom: 28px;
}}

.header-content {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 24px;
}}

.logo {{
    font-size: 30px;
    font-weight: 800;
    letter-spacing: -0.5px;
}}

.subtitle {{
    color: #cbd5e1;
    margin-top: 4px;
}}

.scan-id {{
    color: #cbd5e1;
    font-size: 14px;
}}

.section {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    box-shadow: var(--shadow);
    padding: 24px;
    margin-bottom: 24px;
}}

.section h2 {{
    margin-top: 0;
    margin-bottom: 18px;
    font-size: 20px;
}}

.posture {{
    border-radius: 14px;
    padding: 24px 28px;
    margin-bottom: 24px;
    border: 1px solid;
}}

.posture h2 {{
    margin: 0 0 6px 0;
    font-size: 26px;
}}

.posture p {{
    margin: 0;
}}

.posture-secure {{
    background: var(--secure-bg);
    border-color: #86efac;
    color: var(--secure);
}}

.posture-at-risk {{
    background: var(--at-risk-bg);
    border-color: #fdba74;
    color: var(--at-risk);
}}

.posture-critical {{
    background: var(--status-critical-bg);
    border-color: #fca5a5;
    color: var(--status-critical);
}}

.posture-unknown {{
    background: var(--status-unknown-bg);
    border-color: #cbd5e1;
    color: var(--status-unknown);
}}

.metrics {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}}

.metric {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    box-shadow: var(--shadow);
}}

.metric-label {{
    color: var(--muted);
    font-size: 13px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

.metric-value {{
    margin-top: 6px;
    font-size: 30px;
    font-weight: 800;
}}

.metric-critical .metric-value {{
    color: var(--critical);
}}

.metric-high .metric-value {{
    color: var(--high);
}}

.metric-medium .metric-value {{
    color: var(--medium);
}}

.metric-low .metric-value {{
    color: var(--low);
}}

.metric-score .metric-value {{
    color: #7c3aed;
}}

.grid {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(350px, 1fr));
    gap: 24px;
}}

.info-table {{
    width: 100%;
    border-collapse: collapse;
}}

.info-table td {{
    padding: 9px 4px;
    border-bottom: 1px solid var(--border);
}}

.info-table td:first-child {{
    width: 180px;
    color: var(--muted);
    font-weight: 600;
}}

table.data-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
}}

.data-table th {{
    background: #f1f5f9;
    color: #334155;
    text-align: left;
    padding: 12px;
    border-bottom: 2px solid var(--border);
    white-space: nowrap;
}}

.data-table td {{
    padding: 11px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
}}

.data-table tbody tr:hover {{
    background: #f8fafc;
}}

.badge {{
    display: inline-flex;
    align-items: center;
    padding: 4px 9px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    white-space: nowrap;
}}

.severity-critical {{
    color: var(--critical);
    background: var(--critical-bg);
}}

.severity-high {{
    color: var(--high);
    background: var(--high-bg);
}}

.severity-medium {{
    color: var(--medium);
    background: var(--medium-bg);
}}

.severity-low {{
    color: var(--low);
    background: var(--low-bg);
}}

.severity-unknown {{
    color: var(--unknown);
    background: var(--unknown-bg);
}}

.status-open {{
    color: var(--open);
    background: var(--open-bg);
}}

.status-resolved {{
    color: var(--resolved);
    background: var(--resolved-bg);
}}

.status-unknown {{
    color: var(--unknown);
    background: var(--unknown-bg);
}}

.status-at-risk {{
    color: var(--at-risk);
    background: var(--at-risk-bg);
}}

.status-secure {{
    color: var(--secure);
    background: var(--secure-bg);
}}

.status-critical {{
    color: var(--status-critical);
    background: var(--status-critical-bg);
}}

.status-unknown {{
    color: var(--status-unknown);
    background: var(--status-unknown-bg);
}}

.kev {{
    color: var(--critical);
    background: var(--critical-bg);
}}

.no-kev {{
    color: var(--muted);
    background: #f1f5f9;
}}

.recommendation {{
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 10px;
}}

.recommendation strong {{
    color: #1d4ed8;
}}

.warning {{
    background: #fff7ed;
    border: 1px solid #fed7aa;
    color: #9a3412;
    border-radius: 10px;
    padding: 16px 18px;
}}

.error {{
    background: #fee2e2;
    border: 1px solid #fecaca;
    color: #991b1b;
    border-radius: 10px;
    padding: 16px 18px;
}}

.empty {{
    color: var(--muted);
    font-style: italic;
}}

.footer {{
    text-align: center;
    color: var(--muted);
    font-size: 13px;
    padding: 24px 0 40px;
}}

.table-wrapper {{
    overflow-x: auto;
}}

@media (max-width: 800px) {{
    .container {{
        width: min(100% - 24px, 1500px);
    }}

    .header-content {{
        flex-direction: column;
        align-items: flex-start;
    }}

    .section {{
        padding: 18px;
    }}
}}

</style>
</head>

<body>

<header class="header">
<div class="container header-content">

<div>
    <div class="logo">🛡 Sentinel</div>
    <div class="subtitle">
        Vulnerability & Dependency Security Report
    </div>
</div>

<div class="scan-id">
    Scan #{report.scan_id}
</div>

</div>
</header>

<main class="container">

{self._render_security_posture(report)}

<div class="metrics">

    <div class="metric metric-score">
        <div class="metric-label">Risk Score</div>
        <div class="metric-value">{report.risk_score}</div>
    </div>

    <div class="metric metric-critical">
        <div class="metric-label">Open Critical</div>
        <div class="metric-value">{report.critical_count}</div>
    </div>

    <div class="metric metric-high">
        <div class="metric-label">Open High</div>
        <div class="metric-value">{report.high_count}</div>
    </div>

    <div class="metric metric-medium">
        <div class="metric-label">Open Medium</div>
        <div class="metric-value">{report.medium_count}</div>
    </div>

    <div class="metric metric-low">
        <div class="metric-label">Open Low</div>
        <div class="metric-value">{report.low_count}</div>
    </div>

    <div class="metric">
        <div class="metric-label">Total Findings</div>
        <div class="metric-value">
            {len(report.findings)}
        </div>
    </div>

</div>

<div class="grid">

<section class="section">
<h2>Scan Information</h2>

<table class="info-table">
<tr>
    <td>Scan ID</td>
    <td>{report.scan_id}</td>
</tr>
<tr>
    <td>Repository ID</td>
    <td>{report.repository_id}</td>
</tr>
<tr>
    <td>Profile</td>
    <td>{escape(report.profile_name)}</td>
</tr>
<tr>
    <td>Engine Version</td>
    <td>{escape(report.engine_version)}</td>
</tr>
<tr>
    <td>Scan Status</td>
    <td>{escape(report.status.value)}</td>
</tr>
<tr>
    <td>Started</td>
    <td>{format_datetime(report.started_at)}</td>
</tr>
<tr>
    <td>Finished</td>
    <td>{format_datetime(report.finished_at)}</td>
</tr>
<tr>
    <td>Duration</td>
    <td>{format_duration(report.duration_seconds)}</td>
</tr>
</table>

</section>

<section class="section">
<h2>Source</h2>

<table class="info-table">
<tr>
    <td>Type</td>
    <td>{escape(report.source_type.value)}</td>
</tr>
<tr>
    <td>Reference</td>
    <td>{source_reference}</td>
</tr>
<tr>
    <td>Branch</td>
    <td>{source_branch}</td>
</tr>
<tr>
    <td>Commit</td>
    <td>{source_commit}</td>
</tr>
</table>

</section>

</div>

{error_section}

{self._render_status_summary(report)}

{dependency_security_section}

{recommendations_section}

<section class="section">
<h2>Vulnerabilities</h2>

<div class="table-wrapper">

<table class="data-table">

<thead>
<tr>
    <th>Dependency</th>
    <th>Version</th>
    <th>Ecosystem</th>
    <th>Identifier</th>
    <th>Severity</th>
    <th>Status</th>
    <th>CVSS</th>
    <th>KEV</th>
    <th>EPSS</th>
    <th>Sources</th>
</tr>
</thead>

<tbody>
{findings_rows}
</tbody>

</table>

</div>
</section>

{remediation_section}

{kev_section}

{vulncheck_kev_section}

</main>

<footer class="footer">
    Generated by Sentinel Security Scanner
</footer>

</body>
</html>
"""

    @staticmethod
    def _render_security_posture(
        report: ScanReport,
    ) -> str:
        status = report.security_status

        if status == SecurityStatus.SECURE:
            css_class = "posture-secure"
            title = "Project is secure"
            message = (
                "No currently open vulnerability puts the project at risk."
            )

        elif status == SecurityStatus.AT_RISK:
            css_class = "posture-at-risk"
            title = "Project is at risk"
            message = (
                "The scan detected open vulnerabilities that "
                "require remediation."
            )

        elif status == SecurityStatus.CRITICAL:
            css_class = "posture-critical"
            title = "Critical security risk"
            message = (
                "The scan detected an open critical vulnerability "
                "or a known exploited vulnerability."
            )

        else:
            css_class = "posture-unknown"
            title = "Security posture is unknown"
            message = (
                "The scan contains unresolved findings whose "
                "security impact cannot currently be fully determined."
            )

        return f"""
<section class="posture {css_class}">
    <h2>{title}</h2>
    <p>{message}</p>
</section>
"""

    @staticmethod
    def _render_status_summary(
        report: ScanReport,
    ) -> str:
        status_counts: dict[VulnerabilityStatus, int] = {
            VulnerabilityStatus.OPEN: 0,
            VulnerabilityStatus.RESOLVED: 0,
            VulnerabilityStatus.UNKNOWN: 0,
        }

        for finding in report.findings:
            status = finding.status

            if status in status_counts:
                status_counts[status] += 1

        return f"""
<section class="section">

<h2>Finding Status</h2>

<div class="metrics">

<div class="metric">
    <div class="metric-label">Open</div>
    <div class="metric-value">
        {status_counts[VulnerabilityStatus.OPEN]}
    </div>
</div>

<div class="metric">
    <div class="metric-label">Resolved</div>
    <div class="metric-value">
        {status_counts[VulnerabilityStatus.RESOLVED]}
    </div>
</div>

<div class="metric">
    <div class="metric-label">Unknown</div>
    <div class="metric-value">
        {status_counts[VulnerabilityStatus.UNKNOWN]}
    </div>
</div>

</div>

<p class="empty">
    Security posture and risk score are calculated from
    currently <strong>OPEN</strong> vulnerabilities.
    Resolved vulnerabilities are retained for audit history.
</p>

</section>
"""

    @staticmethod
    def _render_error(
        report: ScanReport,
    ) -> str:
        if not report.error_message:
            return ""

        return f"""
<section class="section">
    <h2>Scan Error</h2>
    <div class="error">
        {escape(report.error_message)}
    </div>
</section>
"""

    @staticmethod
    def _render_findings(
        report: ScanReport,
    ) -> str:
        rows: list[str] = []

        for finding in report.findings:
            severity_value = finding.severity.value
            severity_class = severity_value.lower().replace(" ", "-")

            status_value = finding.status.value
            status_class = status_value.lower()

            severity = (
                f'<span class="badge severity-{severity_class}">'
                f"{escape(severity_value)}"
                "</span>"
            )

            status = (
                f'<span class="badge status-{status_class}">'
                f"{escape(status_value)}"
                "</span>"
            )

            kev_class = "kev" if finding.known_exploited else "no-kev"
            kev_value = "YES" if finding.known_exploited else "NO"

            kev = f'<span class="badge {kev_class}">{kev_value}</span>'

            epss = (
                str(finding.epss_score)
                if finding.epss_score is not None
                else "N/A"
            )

            sources = escape(
                ", ".join(source.value for source in finding.sources)
            )

            rows.append(
                f"""
<tr>
    <td>{escape(finding.dependency_name)}</td>
    <td>{escape(finding.dependency_version)}</td>
    <td>{escape(finding.ecosystem.value)}</td>
    <td>{escape(finding.identifier)}</td>
    <td>{severity}</td>
    <td>{status}</td>
    <td>{finding.cvss}</td>
    <td>{kev}</td>
    <td>{epss}</td>
    <td>{sources}</td>
</tr>
"""
            )

        return "\n".join(rows)

    @staticmethod
    def _render_dependency_security_section(
        report: ScanReport,
    ) -> str:
        if not report.dependency_summaries:
            return ""

        rows: list[str] = []

        for summary in report.dependency_summaries:
            status = summary.security_status.value
            status_class = status.lower().replace("_", "-")

            status_badge = (
                f'<span class="badge status-{status_class}">'
                f"{escape(status)}"
                "</span>"
            )

            recommended_version = (
                escape(summary.recommended_version)
                if summary.recommended_version is not None
                else "N/A"
            )

            rows.append(
                f"""
<tr>
    <td><strong>{escape(summary.dependency_name)}</strong></td>
    <td>{escape(summary.installed_version)}</td>
    <td>{escape(summary.ecosystem.value)}</td>
    <td>{status_badge}</td>
    <td>{summary.finding_count}</td>
    <td>{summary.open_finding_count}</td>
    <td>{recommended_version}</td>
</tr>
"""
            )

        return f"""
<section class="section">

<h2>Dependency Security</h2>

<p class="empty">
    Security posture calculated for each dependency.
</p>

<div class="table-wrapper">

<table class="data-table">

<thead>
<tr>
    <th>Dependency</th>
    <th>Installed Version</th>
    <th>Ecosystem</th>
    <th>Security Status</th>
    <th>Findings</th>
    <th>Open Findings</th>
    <th>Recommended Version</th>
</tr>
</thead>

<tbody>
{"".join(rows)}
</tbody>

</table>

</div>

</section>
"""

    @staticmethod
    def _render_recommendations(
        report: ScanReport,
    ) -> str:
        actions: list[str] = []

        for summary in report.dependency_summaries:
            if summary.recommended_version is None:
                continue

            actions.append(
                f"""
<div class="recommendation">
    <strong>{escape(summary.dependency_name)}</strong>
    should be upgraded from
    <strong>{escape(summary.installed_version)}</strong>
    to at least
    <strong>{escape(summary.recommended_version)}</strong>.
</div>
"""
            )

        if not actions:
            return """
<section class="section">
<h2>Recommended Actions</h2>

<p class="empty">
    No immediate dependency upgrade recommendation is available.
</p>

</section>
"""

        return f"""
<section class="section">

<h2>Recommended Actions</h2>

{"".join(actions)}

</section>
"""

    @staticmethod
    def _render_remediation_section(
        report: ScanReport,
    ) -> str:
        findings_with_remediation = [
            finding
            for finding in report.findings
            if (
                finding.status == VulnerabilityStatus.OPEN
                and (finding.remediation is not None or finding.fixed_versions)
            )
        ]

        if not findings_with_remediation:
            return ""

        sections: list[str] = [
            """
<section class="section">
<h2>Remediation</h2>
"""
        ]

        for finding in findings_with_remediation:
            sections.append(
                f"""
<h3>
    {escape(finding.dependency_name)}
    {escape(finding.dependency_version)}
    -
    {escape(finding.identifier)}
</h3>
"""
            )

            if finding.remediation is not None:
                rows: list[str] = []

                for rule in finding.remediation.rules:
                    introduced = (
                        escape(rule.introduced)
                        if rule.introduced is not None
                        else "N/A"
                    )

                    fixed = (
                        escape(rule.fixed) if rule.fixed is not None else "N/A"
                    )

                    affected_range = (
                        escape(rule.affected_range)
                        if rule.affected_range is not None
                        else "N/A"
                    )

                    rows.append(
                        f"""
<tr>
    <td>{introduced}</td>
    <td>{fixed}</td>
    <td>{affected_range}</td>
</tr>
"""
                    )

                sections.append(
                    f"""
<div class="table-wrapper">
<table class="data-table">
<thead>
<tr>
    <th>Introduced</th>
    <th>Fixed</th>
    <th>Affected Range</th>
</tr>
</thead>
<tbody>
{"".join(rows)}
</tbody>
</table>
</div>
"""
                )

            if finding.fixed_versions:
                versions = "".join(
                    f"<li>{escape(version)}</li>"
                    for version in finding.fixed_versions
                )

                sections.append(
                    f"""
<p><strong>Fixed versions:</strong></p>
<ul>
{versions}
</ul>
"""
                )

        sections.append("</section>")

        return "\n".join(sections)

    @staticmethod
    def _render_kev_section(
        report: ScanReport,
    ) -> str:
        kev_findings = [
            finding
            for finding in report.findings
            if (
                finding.known_exploited
                and finding.status == VulnerabilityStatus.OPEN
            )
        ]

        if not kev_findings:
            return ""

        rows: list[str] = []

        for finding in kev_findings:
            added_date = (
                str(finding.kev_date_added)
                if finding.kev_date_added is not None
                else "N/A"
            )

            vendor = (
                escape(finding.kev_vendor)
                if finding.kev_vendor is not None
                else "N/A"
            )

            product = (
                escape(finding.kev_product)
                if finding.kev_product is not None
                else "N/A"
            )

            ransomware = (
                escape(finding.kev_known_ransomware)
                if finding.kev_known_ransomware is not None
                else "N/A"
            )

            required_action = (
                escape(finding.kev_required_action)
                if finding.kev_required_action is not None
                else "N/A"
            )

            rows.append(
                f"""
<tr>
    <td>{escape(finding.dependency_name)}</td>
    <td>{escape(finding.identifier)}</td>
    <td>{vendor}</td>
    <td>{product}</td>
    <td>{added_date}</td>
    <td>{ransomware}</td>
    <td>{required_action}</td>
</tr>
"""
            )

        return f"""
<section class="section">

<h2>🚨 Known Exploited Vulnerabilities</h2>

<div class="warning">
    These vulnerabilities are currently open and are known
    to have been exploited in the wild.
</div>

<br>

<div class="table-wrapper">

<table class="data-table">

<thead>
<tr>
    <th>Dependency</th>
    <th>Identifier</th>
    <th>Vendor</th>
    <th>Product</th>
    <th>Added Date</th>
    <th>Ransomware</th>
    <th>Required Action</th>
</tr>
</thead>

<tbody>
{"".join(rows)}
</tbody>

</table>

</div>

</section>
"""

    @staticmethod
    def _render_vulncheck_kev_section(
        report: ScanReport,
    ) -> str:
        vulncheck_findings = [
            finding
            for finding in report.findings
            if (
                finding.vulncheck_known_exploited
                and finding.status == VulnerabilityStatus.OPEN
            )
        ]

        if not vulncheck_findings:
            return ""

        rows: list[str] = []

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
                escape(finding.vulncheck_vendor)
                if finding.vulncheck_vendor is not None
                else "N/A"
            )

            product = (
                escape(finding.vulncheck_product)
                if finding.vulncheck_product is not None
                else "N/A"
            )

            ransomware = (
                escape(finding.vulncheck_known_ransomware)
                if finding.vulncheck_known_ransomware is not None
                else "N/A"
            )

            required_action = (
                escape(finding.vulncheck_required_action)
                if finding.vulncheck_required_action is not None
                else "N/A"
            )

            canaries = (
                "YES"
                if finding.vulncheck_reported_exploited_by_canaries
                else "NO"
            )

            rows.append(
                f"""
<tr>
    <td>{escape(finding.dependency_name)}</td>
    <td>{escape(finding.identifier)}</td>
    <td>{vendor}</td>
    <td>{product}</td>
    <td>{date_added}</td>
    <td>{cisa_date_added}</td>
    <td>{due_date}</td>
    <td>{ransomware}</td>
    <td>{canaries}</td>
    <td>{required_action}</td>
</tr>
"""
            )

        return f"""
<section class="section">

<h2>🚨 VulnCheck Known Exploited Vulnerabilities</h2>

<div class="warning">
    These vulnerabilities are currently open and are known
    to have been exploited according to VulnCheck intelligence.
</div>

<br>

<div class="table-wrapper">

<table class="data-table">

<thead>
<tr>
    <th>Dependency</th>
    <th>Identifier</th>
    <th>Vendor</th>
    <th>Product</th>
    <th>Added Date</th>
    <th>CISA Added Date</th>
    <th>Due Date</th>
    <th>Ransomware</th>
    <th>Canaries</th>
    <th>Required Action</th>
</tr>
</thead>

<tbody>
{"".join(rows)}
</tbody>

</table>

</div>

</section>
"""
