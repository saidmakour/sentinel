from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class GHSAIdentifier:
    """
    Vulnerability identifier returned by GHSA.
    """

    type: str
    value: str


@dataclass(slots=True, frozen=True)
class GHSAPackage:
    """
    Affected package returned by GHSA.
    """

    ecosystem: str
    name: str
    first_patched_version: str | None = None
    vulnerable_version_range: str | None = None


@dataclass(slots=True, frozen=True)
class GHSACVSS:
    """
    CVSS severity information returned by GHSA.
    """

    vector_string: str | None = None
    score: float | None = None


@dataclass(slots=True, frozen=True)
class GHSAVulnerability:
    """
    Single vulnerability advisory returned by GHSA.
    """

    ghsa_id: str
    cve_id: str | None
    summary: str
    description: str
    severity: str

    identifiers: list[GHSAIdentifier]

    package: GHSAPackage | None = None

    cvss_v3: GHSACVSS | None = None
    cvss_v4: GHSACVSS | None = None

    @property
    def cvss_score(self) -> float | None:
        """
        Return the highest available CVSS score.

        CVSS v4 is preferred when available.
        """
        scores = [
            cvss.score
            for cvss in (
                self.cvss_v4,
                self.cvss_v3,
            )
            if cvss is not None and cvss.score is not None
        ]

        return max(scores) if scores else None

    @property
    def aliases(self) -> list[str]:
        """
        Return all vulnerability identifiers except the canonical GHSA ID.
        """
        return [
            identifier.value
            for identifier in self.identifiers
            if identifier.value != self.ghsa_id
        ]


@dataclass(slots=True, frozen=True)
class GHSAResponse:
    """
    Response returned by the GHSA API.
    """

    vulnerabilities: list[GHSAVulnerability]
