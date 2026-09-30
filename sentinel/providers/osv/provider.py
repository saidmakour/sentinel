from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.provider import Provider
from sentinel.providers.base import BaseProvider
from sentinel.providers.osv.client import OSVClient
from sentinel.providers.osv.mapper import OSVMapper


class OSVProvider(BaseProvider):
    name = Provider.OSV

    def __init__(
        self,
        client: OSVClient | None = None,
        mapper: OSVMapper | None = None,
    ) -> None:
        self.client = client or OSVClient()
        self.mapper = mapper or OSVMapper()

    def scan(
        self,
        dependency: ScannedDependency,
    ) -> list[VulnerabilityInfo]:
        response = self.client.query(
            package_name=dependency.name,
            version=dependency.version,
            ecosystem=dependency.ecosystem,
        )

        return self.mapper.map(
            dependency,
            response,
        )
