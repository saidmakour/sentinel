from __future__ import annotations

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.provider import Provider
from sentinel.providers.base import BaseProvider
from sentinel.providers.github.client import GitHubAdvisoryClient
from sentinel.providers.github.mapper import GitHubAdvisoryMapper
from sentinel.providers.github.models import GitHubAdvisory
from sentinel.providers.github.parser import GitHubAdvisoryParser


class GitHubAdvisoryProvider(BaseProvider):
    """
    GitHub Global Security Advisory vulnerability provider.
    """

    name = Provider.GITHUB_ADVISORY

    def __init__(
        self,
        client: GitHubAdvisoryClient | None = None,
        parser: GitHubAdvisoryParser | None = None,
        mapper: GitHubAdvisoryMapper | None = None,
    ) -> None:
        self.client = client or GitHubAdvisoryClient()
        self.parser = parser or GitHubAdvisoryParser()
        self.mapper = mapper or GitHubAdvisoryMapper()

    def scan(
        self,
        dependency: ScannedDependency,
    ) -> list[VulnerabilityInfo]:
        advisories_data = self.client.query(
            package_name=dependency.name,
            version=dependency.version,
            ecosystem=self._github_ecosystem(
                dependency.ecosystem.value,
            ),
        )

        advisories: list[GitHubAdvisory] = []

        for advisory_data in advisories_data:
            advisory = self.parser.parse(advisory_data)

            if advisory is not None:
                advisories.append(advisory)

        return self.mapper.map(
            dependency,
            advisories,
        )

    @staticmethod
    def _github_ecosystem(
        ecosystem: str,
    ) -> str:
        mapping = {
            "python": "pip",
            "pip": "pip",
            "npm": "npm",
            "node": "npm",
            "java": "maven",
            "maven": "maven",
            "php": "composer",
            "composer": "composer",
            "go": "go",
            "rust": "rust",
            "ruby": "rubygems",
            "rubygems": "rubygems",
            "nuget": "nuget",
            "swift": "swift",
            "erlang": "erlang",
            "dart": "pub",
        }

        return mapping.get(
            ecosystem.lower(),
            ecosystem.lower(),
        )
