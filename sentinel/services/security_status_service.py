from collections.abc import Iterable

from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.security_status import SecurityStatus
from sentinel.enums.severity import Severity
from sentinel.enums.vulnerability_status import VulnerabilityStatus


class SecurityStatusService:
    """
    | Findings                         | Security status |
    | -------------------------------- | --------------- |
    | Aucun finding                    | SECURE          |
    | Tous les findings RESOLVED       | SECURE          |
    | UNKNOWN uniquement               | UNKNOWN         |
    | RESOLVED + UNKNOWN               | UNKNOWN         |
    | OPEN LOW/MEDIUM/HIGH             | AT_RISK         |
    | OPEN CRITICAL                    | CRITICAL        |
    | OPEN + CISA KEV                  | CRITICAL        |
    | OPEN + VulnCheck KEV             | CRITICAL        |
    """

    def calculate(
        self,
        findings: Iterable[VulnerabilityInfo],
    ) -> SecurityStatus:
        findings = list(findings)

        if not findings:
            return SecurityStatus.SECURE

        open_findings = [
            finding
            for finding in findings
            if finding.status == VulnerabilityStatus.OPEN
        ]

        unknown_findings = [
            finding
            for finding in findings
            if finding.status == VulnerabilityStatus.UNKNOWN
        ]
        """
        if any(
            finding.known_exploited or finding.severity == Severity.CRITICAL
            for finding in open_findings
        ):
        """
        if any(
            finding.known_exploited
            or finding.vulncheck_known_exploited
            or finding.severity == Severity.CRITICAL
            for finding in open_findings
        ):
            return SecurityStatus.CRITICAL

        if open_findings:
            return SecurityStatus.AT_RISK

        if unknown_findings:
            return SecurityStatus.UNKNOWN

        return SecurityStatus.SECURE
