from dataclasses import dataclass
from dataclasses import field

from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule


@dataclass(slots=True, frozen=True)
class OSVSeverity:
    """
    Severity entry returned by OSV.
    """

    type: str
    score: str


@dataclass(slots=True, frozen=True)
class OSVEvent:
    """
    Version event returned by OSV ranges.
    """

    introduced: str | None = None
    fixed: str | None = None


@dataclass(slots=True, frozen=True)
class OSVRange:
    """
    Version range affected by vulnerability.
    """

    type: str
    events: list[OSVEvent] = field(
        default_factory=list[OSVEvent],
    )


@dataclass(slots=True, frozen=True)
class OSVAffected:
    """
    Package affected by vulnerability.
    """

    package_name: str
    ranges: list[OSVRange] = field(
        default_factory=list[OSVRange],
    )


@dataclass(slots=True, frozen=True)
class OSVVulnerability:
    """
    Single vulnerability returned by OSV.
    """

    identifier: str

    aliases: list[str]

    summary: str

    severity: list[OSVSeverity]

    affected: list[OSVAffected] = field(
        default_factory=list[OSVAffected],
    )

    @property
    def fixed_versions(self) -> list[str]:
        """
        Extract fixed versions from OSV ranges.
        """

        versions: list[str] = []

        for affected in self.affected:
            for osv_range in affected.ranges:
                for event in osv_range.events:
                    if event.fixed:
                        versions.append(
                            event.fixed,
                        )

        return list(
            dict.fromkeys(
                versions,
            )
        )

    @property
    def remediation(self) -> RemediationInfo:
        rules: list[RemediationRule] = []

        for affected in self.affected:
            for osv_range in affected.ranges:
                introduced: str | None = None

                for event in osv_range.events:
                    if event.introduced is not None:
                        introduced = event.introduced

                    if event.fixed is not None:
                        rules.append(
                            RemediationRule(
                                introduced=introduced,
                                fixed=event.fixed,
                            )
                        )
                        introduced = None

                if introduced is not None:
                    rules.append(
                        RemediationRule(
                            introduced=introduced,
                        )
                    )

        return RemediationInfo(
            rules=rules,
        )

    @property
    def cvss(self) -> float | None:
        """
        Return the first CVSS score if available.
        """

        if not self.severity:
            return None

        try:
            return float(
                self.severity[0].score,
            )

        except (TypeError, ValueError):
            return None


@dataclass(slots=True, frozen=True)
class OSVResponse:
    """
    Response returned by the OSV API.
    """

    vulns: list[OSVVulnerability]
