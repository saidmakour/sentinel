from sentinel.providers.ghsa.models import GHSAIdentifier
from sentinel.providers.ghsa.models import GHSAPackage
from sentinel.providers.ghsa.models import GHSAResponse
from sentinel.providers.ghsa.models import GHSAVulnerability


def test_ghsa_identifier_can_be_created() -> None:
    identifier = GHSAIdentifier(
        type="GHSA",
        value="GHSA-xxxx-yyyy-zzzz",
    )

    assert identifier.type == "GHSA"
    assert identifier.value == "GHSA-xxxx-yyyy-zzzz"


def test_ghsa_package_can_be_created() -> None:
    package = GHSAPackage(
        ecosystem="pip",
        name="requests",
    )

    assert package.ecosystem == "pip"
    assert package.name == "requests"


def test_ghsa_vulnerability_can_be_created() -> None:
    vulnerability = GHSAVulnerability(
        ghsa_id="GHSA-xxxx-yyyy-zzzz",
        cve_id="CVE-2026-1234",
        summary="Example vulnerability",
        severity="HIGH",
        identifiers=[],
        description="",
    )

    assert vulnerability.ghsa_id == "GHSA-xxxx-yyyy-zzzz"
    assert vulnerability.cve_id == "CVE-2026-1234"
    assert vulnerability.summary == "Example vulnerability"
    assert vulnerability.severity == "HIGH"
    assert vulnerability.identifiers == []
    assert vulnerability.package is None
    assert vulnerability.cvss_score is None


def test_ghsa_response_can_be_created() -> None:
    vulnerability = GHSAVulnerability(
        ghsa_id="GHSA-xxxx-yyyy-zzzz",
        cve_id=None,
        summary="Example",
        severity="LOW",
        identifiers=[],
        description="",
    )

    response = GHSAResponse(
        vulnerabilities=[vulnerability],
    )

    assert len(response.vulnerabilities) == 1
    assert response.vulnerabilities[0] is vulnerability
