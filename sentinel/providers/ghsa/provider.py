from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.provider import Provider
from sentinel.providers.base import BaseProvider
from sentinel.providers.ghsa.client import GHSAClient
from sentinel.providers.ghsa.mapper import GHSAMapper


class GHSAProvider(BaseProvider):
    name = Provider.GHSA

    def __init__(
        self,
        client: GHSAClient | None = None,
        mapper: GHSAMapper | None = None,
    ) -> None:
        self.client = client or GHSAClient()
        self.mapper = mapper or GHSAMapper()

    def scan(
        self,
        dependency: ScannedDependency,
    ) -> list[VulnerabilityInfo]:
        response = self.client.query(
            package_name=dependency.name,
            ecosystem=dependency.ecosystem,
        )

        return self.mapper.map(
            dependency,
            response,
        )
