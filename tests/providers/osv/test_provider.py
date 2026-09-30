from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.providers.osv.models import OSVResponse
from sentinel.providers.osv.models import OSVVulnerability
from sentinel.providers.osv.provider import OSVProvider


class FakeClient:
    def __init__(self) -> None:
        self.called = False
        self.arguments: tuple[str, str, str] | None = None

    def query(
        self,
        package_name: str,
        version: str,
        ecosystem: str,
    ) -> OSVResponse:
        self.called = True

        self.arguments = (
            package_name,
            version,
            ecosystem,
        )

        return OSVResponse(
            vulns=[
                OSVVulnerability(
                    identifier="CVE-2026-0001",
                    aliases=[
                        "CVE-2026-0001",
                    ],
                    summary="",
                    severity=[],
                )
            ]
        )


class FakeMapper:
    def __init__(self) -> None:
        self.called = False
        self.arguments: (
            tuple[
                ScannedDependency,
                OSVResponse,
            ]
            | None
        ) = None

    def map(
        self,
        dependency: ScannedDependency,
        response: OSVResponse,
    ) -> list[str]:
        self.called = True

        self.arguments = (
            dependency,
            response,
        )

        return ["mapped"]


def test_provider_calls_client_and_mapper() -> None:
    client = FakeClient()
    mapper = FakeMapper()

    provider = OSVProvider(
        client=client,
        mapper=mapper,
    )

    dependency = ScannedDependency(
        name="requests",
        version="2.32.3",
        ecosystem="PyPI",
        source="requirements.txt",
        priority=40,
    )

    result = provider.scan(dependency)

    assert client.called
    assert mapper.called

    assert client.arguments == (
        "requests",
        "2.32.3",
        "PyPI",
    )

    assert mapper.arguments is not None

    scanned_dependency, response = mapper.arguments

    assert scanned_dependency is dependency

    assert isinstance(response, OSVResponse)

    assert len(response.vulns) == 1

    assert response.vulns[0].identifier == "CVE-2026-0001"

    assert result == ["mapped"]


def test_provider_uses_default_dependencies() -> None:
    provider = OSVProvider()

    assert provider.client is not None
    assert provider.mapper is not None
