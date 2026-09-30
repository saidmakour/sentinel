from sentinel.dto.scan_result import ScanResult
from sentinel.renderers.base import BaseRenderer


class MarkdownRenderer(BaseRenderer):
    def render(
        self,
        result: ScanResult,
    ) -> str:

        if not result.findings:
            return (
                "# Sentinel Report\n\n"
                "No vulnerabilities found.\n\n"
                "## Summary\n\n"
                f"- Dependencies: "
                f"{result.statistics.dependency_count}\n"
                "- Findings: 0\n"
            )

        lines: list[str] = [
            "# Sentinel Report",
            "",
            "## Summary",
            "",
            (f"- Dependencies: {result.statistics.dependency_count}"),
            (f"- Findings: {result.statistics.finding_count}"),
            "",
            "### Severity",
            "",
            (f"- Critical: {result.statistics.severity.critical}"),
            (f"- High: {result.statistics.severity.high}"),
            (f"- Medium: {result.statistics.severity.medium}"),
            (f"- Low: {result.statistics.severity.low}"),
            (f"- Unknown: {result.statistics.severity.unknown}"),
            "",
            "## Vulnerabilities",
            "",
        ]

        for finding in result.findings:
            epss_score = (
                str(finding.epss_score)
                if finding.epss_score is not None
                else "N/A"
            )

            sources = ", ".join(source.value for source in finding.sources)

            lines.extend(
                [
                    (
                        f"## {finding.dependency_name} "
                        f"{finding.dependency_version}"
                    ),
                    "",
                    "| Field | Value |",
                    "|-------|-------|",
                    f"| CVE | {finding.identifier} |",
                    (f"| Severity | {finding.severity.value} |"),
                    f"| CVSS | {finding.cvss} |",
                    f"| Provider | {sources} |",
                    (
                        "| Known Exploited | "
                        f"{'Yes' if finding.known_exploited else 'No'} |"
                    ),
                    (
                        "| VulnCheck KEV | "
                        f"{'Yes' if finding.vulncheck_known_exploited else 'No'} |"
                    ),
                    f"| EPSS Score | {epss_score} |",
                    (f"| EPSS Percentile | {finding.epss_percentile} |"),
                    "",
                    "### Summary",
                    "",
                    finding.summary,
                    "",
                ]
            )

            if finding.vulncheck_known_exploited:
                lines.extend(
                    [
                        "### VulnCheck Known Exploited",
                        "",
                        "| Field | Value |",
                        "|-------|-------|",
                        (f"| Vendor | {finding.vulncheck_vendor or 'N/A'} |"),
                        (
                            f"| Product | "
                            f"{finding.vulncheck_product or 'N/A'} |"
                        ),
                        (
                            f"| Added Date | "
                            f"{finding.vulncheck_date_added or 'N/A'} |"
                        ),
                        (
                            f"| CISA Added Date | "
                            f"{finding.vulncheck_cisa_date_added or 'N/A'} |"
                        ),
                        (
                            f"| Due Date | "
                            f"{finding.vulncheck_due_date or 'N/A'} |"
                        ),
                        (
                            f"| Ransomware | "
                            f"{finding.vulncheck_known_ransomware or 'N/A'} |"
                        ),
                        (
                            "| Reported by Canaries | "
                            f"{'Yes' if finding.vulncheck_reported_exploited_by_canaries else 'No'} |"
                        ),
                    ]
                )

                if finding.vulncheck_required_action is not None:
                    lines.extend(
                        [
                            "",
                            "**Required Action:** "
                            f"{finding.vulncheck_required_action}",
                        ]
                    )

                lines.extend(
                    [
                        "",
                    ]
                )

            lines.extend(
                [
                    "---",
                    "",
                ]
            )

        return "\n".join(lines)
