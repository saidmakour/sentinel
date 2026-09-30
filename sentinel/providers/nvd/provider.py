from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.provider import Provider
from sentinel.log.logger import get_logger
from sentinel.providers.base import BaseProvider
from sentinel.providers.nvd.client import NVDClient
from sentinel.providers.nvd.mapper import NVDMapper

logger = get_logger(__name__)


class NVDProvider(BaseProvider):
    name = Provider.NVD

    def __init__(
        self,
        client: NVDClient | None = None,
        mapper: NVDMapper | None = None,
    ) -> None:
        self.client = client or NVDClient()
        self.mapper = mapper or NVDMapper()

    def scan(
        self,
        dependency: ScannedDependency,
    ) -> list[VulnerabilityInfo]:

        response = self.client.query(
            package_name=dependency.name,
        )
        logger.debug(
            "NVDProvider.scan START dependency=%s version=%s",
            dependency.name,
            dependency.version,
        )

        vulnerabilities = self.mapper.map(
            dependency,
            response,
        )
        logger.debug(
            "NVDProvider.scan END findings=%d ids=%s",
            len(vulnerabilities),
            [v.identifier for v in vulnerabilities],
        )

        return vulnerabilities
