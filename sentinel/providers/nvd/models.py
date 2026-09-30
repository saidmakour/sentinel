from dataclasses import dataclass
from dataclasses import field


@dataclass(slots=True, frozen=True)
class NVDMetric:
    """
    CVSS metric returned by NVD.
    """

    score: float | None


@dataclass(slots=True, frozen=True)
class NVDVersionRange:
    criteria: str

    version_start_including: str | None = None
    version_start_excluding: str | None = None

    version_end_including: str | None = None
    version_end_excluding: str | None = None

    @property
    def vendor(self) -> str | None:
        """
        Extract vendor from CPE.
        """

        parts = self.criteria.split(":")

        if len(parts) < 5:
            return None

        value = parts[3]

        if value in {"*", "-"}:
            return None

        return value.lower()

    @property
    def product(self) -> str | None:
        """
        Extract product from CPE.
        """

        parts = self.criteria.split(":")

        if len(parts) < 6:
            return None

        value = parts[4]

        if value in {"*", "-"}:
            return None

        return value.lower()

    @property
    def version(self) -> str | None:
        """
        Extract exact version from CPE 2.3.
        """

        parts = self.criteria.split(":")

        if len(parts) < 6:
            return None

        value = parts[5]

        if value in {"*", "-"}:
            return None

        return value.lower()

    @property
    def target_software(self) -> str | None:
        """
        Extract target software from CPE 2.3.
        """

        parts = self.criteria.split(":")

        if len(parts) < 11:
            return None

        value = parts[10]

        if value in {"*", "-"}:
            return None

        return value.lower()


@dataclass(slots=True, frozen=True)
class NVDVulnerability:
    """
    Single vulnerability returned by NVD.
    """

    identifier: str
    aliases: list[str]
    summary: str
    metric: NVDMetric

    configurations: list[NVDVersionRange] = field(
        default_factory=list[NVDVersionRange],
    )

    @property
    def cvss(self) -> float | None:
        return self.metric.score


@dataclass(slots=True, frozen=True)
class NVDResponse:
    """
    Response returned by the NVD API.
    """

    vulnerabilities: list[NVDVulnerability]
