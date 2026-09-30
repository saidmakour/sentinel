from sentinel.dto.scan_result import ScanResult
from sentinel.renderers.base import BaseRenderer


class ConsoleRenderer(BaseRenderer):
    def render(
        self,
        result: ScanResult,
    ) -> str:

        if not result.findings:
            return (
                "No vulnerabilities found.\n\n"
                f"Dependencies : "
                f"{result.statistics.dependency_count}"
            )

        lines: list[str] = [
            "Sentinel Report",
            "===============",
            "",
            (f"Dependencies : {result.statistics.dependency_count}"),
            (f"Findings     : {result.statistics.finding_count}"),
            "",
            "Severity",
            "--------",
            (f"Critical : {result.statistics.severity.critical}"),
            (f"High     : {result.statistics.severity.high}"),
            (f"Medium   : {result.statistics.severity.medium}"),
            (f"Low      : {result.statistics.severity.low}"),
            (f"Unknown  : {result.statistics.severity.unknown}"),
            "",
        ]

        for finding in result.findings:
            sources = ", ".join(source.value for source in finding.sources)

            vulncheck_kev = (
                "YES" if finding.vulncheck_known_exploited else "NO"
            )

            lines.extend(
                [
                    (
                        f"Dependency : "
                        f"{finding.dependency_name} "
                        f"{finding.dependency_version}"
                    ),
                    (f"CVE        : {finding.identifier}"),
                    (f"Severity   : {finding.severity.value}"),
                    (f"CVSS       : {finding.cvss}"),
                    (f"Provider   : {sources}"),
                    (f"VulnCheck KEV : {vulncheck_kev}"),
                    (f"Summary    : {finding.summary}"),
                ]
            )

            if finding.vulncheck_known_exploited:
                if finding.vulncheck_required_action is not None:
                    lines.append(
                        f"VulnCheck Action : "
                        f"{finding.vulncheck_required_action}"
                    )

                ransomware = (
                    finding.vulncheck_known_ransomware
                    if finding.vulncheck_known_ransomware is not None
                    else "N/A"
                )

                canaries = (
                    "YES"
                    if finding.vulncheck_reported_exploited_by_canaries
                    else "NO"
                )

                lines.extend(
                    [
                        (f"Ransomware : {ransomware}"),
                        (f"Canaries   : {canaries}"),
                    ]
                )

            lines.append("")

        return "\n".join(lines)
