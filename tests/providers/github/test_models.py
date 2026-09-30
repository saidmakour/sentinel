from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.ecosystem import Ecosystem
from sentinel.providers.github.mapper import GitHubAdvisoryMapper
from sentinel.providers.github.models import GitHubAdvisory
from sentinel.providers.github.models import GitHubCVSS
from sentinel.providers.github.models import GitHubCVSSSeverities
from sentinel.providers.github.models import GitHubIdentifier
from sentinel.providers.github.models import GitHubPackage
from sentinel.providers.github.models import GitHubVulnerability


def test_github_identifier() -> None:
    identifier = GitHubIdentifier(
        type="CVE",
        value="CVE-2026-1234",
    )

    assert identifier.type == "CVE"
    assert identifier.value == "CVE-2026-1234"


def test_github_package() -> None:
    package = GitHubPackage(
        ecosystem="pip",
        name="requests",
    )

    assert package.ecosystem == "pip"
    assert package.name == "requests"


def test_github_vulnerability() -> None:
    vulnerability = GitHubVulnerability(
        package=GitHubPackage(
            ecosystem="pip",
            name="requests",
        ),
        vulnerable_version_range="<2.32.0",
        first_patched_version="2.32.0",
        vulnerable_functions=["foo", "bar"],
    )

    assert vulnerability.package.ecosystem == "pip"
    assert vulnerability.package.name == "requests"
    assert vulnerability.vulnerable_version_range == "<2.32.0"
    assert vulnerability.first_patched_version == "2.32.0"
    assert vulnerability.vulnerable_functions == ["foo", "bar"]


def test_github_vulnerability_defaults() -> None:
    vulnerability = GitHubVulnerability(
        package=GitHubPackage(
            ecosystem="pip",
            name="requests",
        ),
        vulnerable_version_range="<2.32.0",
    )

    assert vulnerability.first_patched_version is None
    assert vulnerability.vulnerable_functions == []


def test_github_cvss() -> None:
    cvss = GitHubCVSS(
        score=9.8,
        vector_string=("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    )

    assert cvss.score == 9.8
    assert cvss.vector_string is not None


def test_github_cvss_defaults() -> None:
    cvss = GitHubCVSS()

    assert cvss.score is None
    assert cvss.vector_string is None


def test_github_cvss_severities() -> None:
    cvss_v3 = GitHubCVSS(score=7.5)
    cvss_v4 = GitHubCVSS(score=8.2)

    severities = GitHubCVSSSeverities(
        cvss_v3=cvss_v3,
        cvss_v4=cvss_v4,
    )

    assert severities.cvss_v3 == cvss_v3
    assert severities.cvss_v4 == cvss_v4


def test_github_cvss_severities_defaults() -> None:
    severities = GitHubCVSSSeverities()

    assert severities.cvss_v3 is None
    assert severities.cvss_v4 is None


def test_github_advisory() -> None:
    advisory = GitHubAdvisory(
        ghsa_id="GHSA-abcd-1234-efgh",
        summary="Test vulnerability",
        description="A test vulnerability.",
        severity="high",
        cve_id="CVE-2026-1234",
        identifiers=[
            GitHubIdentifier(
                type="GHSA",
                value="GHSA-abcd-1234-efgh",
            ),
            GitHubIdentifier(
                type="CVE",
                value="CVE-2026-1234",
            ),
        ],
        vulnerabilities=[
            GitHubVulnerability(
                package=GitHubPackage(
                    ecosystem="pip",
                    name="requests",
                ),
                vulnerable_version_range="<2.32.0",
                first_patched_version="2.32.0",
            ),
        ],
        cvss=GitHubCVSS(score=8.1),
        cvss_severities=GitHubCVSSSeverities(
            cvss_v3=GitHubCVSS(score=8.1),
            cvss_v4=GitHubCVSS(score=8.5),
        ),
        published_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-02T00:00:00Z",
        references=[
            "https://example.com/advisory",
        ],
    )

    assert advisory.ghsa_id == "GHSA-abcd-1234-efgh"
    assert advisory.cve_id == "CVE-2026-1234"
    assert advisory.severity == "high"
    assert len(advisory.identifiers) == 2
    assert len(advisory.vulnerabilities) == 1
    assert advisory.cvss is not None
    assert advisory.cvss.score == 8.1
    assert advisory.cvss_severities is not None
    assert advisory.cvss_severities.cvss_v4 is not None
    assert advisory.cvss_severities.cvss_v4.score == 8.5
    assert advisory.withdrawn_at is None
    assert advisory.references == [
        "https://example.com/advisory",
    ]


def test_github_advisory_defaults() -> None:
    advisory = GitHubAdvisory(
        ghsa_id="GHSA-abcd-1234-efgh",
        summary="Test vulnerability",
        description=None,
        severity="unknown",
        cve_id=None,
        identifiers=[],
        vulnerabilities=[],
    )

    assert advisory.cvss is None
    assert advisory.cvss_severities is None
    assert advisory.published_at is None
    assert advisory.updated_at is None
    assert advisory.withdrawn_at is None
    assert advisory.references == []


def test_map_remediation() -> None:
    dependency = ScannedDependency(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
    )

    advisory = GitHubAdvisory(
        ghsa_id="GHSA-test",
        summary="Test vulnerability",
        description="Test",
        severity="HIGH",
        cve_id=None,
        identifiers=[],
        vulnerabilities=[
            GitHubVulnerability(
                package=GitHubPackage(
                    ecosystem="pip",
                    name="requests",
                ),
                vulnerable_version_range=">=2.0.0,<2.32.0",
                first_patched_version="2.32.0",
            ),
        ],
    )

    mapper = GitHubAdvisoryMapper()

    result = mapper._map_advisory(
        advisory,
        dependency,
    )

    assert result.remediation == RemediationInfo(
        rules=[
            RemediationRule(
                affected_range=">=2.0.0,<2.32.0",
                fixed="2.32.0",
            ),
        ],
    )


def test_map_multiple_remediation_rules() -> None:

    dependency = ScannedDependency(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
    )

    advisory = GitHubAdvisory(
        ghsa_id="GHSA-test",
        summary="Test vulnerability",
        description="Test",
        severity="HIGH",
        cve_id=None,
        identifiers=[],
        vulnerabilities=[
            GitHubVulnerability(
                package=GitHubPackage(
                    ecosystem="pip",
                    name="requests",
                ),
                vulnerable_version_range=">=2.0.0,<2.20.0",
                first_patched_version="2.20.0",
            ),
            GitHubVulnerability(
                package=GitHubPackage(
                    ecosystem="pip",
                    name="requests",
                ),
                vulnerable_version_range=">=2.25.0,<2.26.0",
                first_patched_version="2.26.0",
            ),
        ],
    )
    mapper = GitHubAdvisoryMapper()
    result = mapper._map_advisory(advisory, dependency)

    assert result.remediation == RemediationInfo(
        rules=[
            RemediationRule(
                affected_range=">=2.0.0,<2.20.0",
                fixed="2.20.0",
            ),
            RemediationRule(
                affected_range=">=2.25.0,<2.26.0",
                fixed="2.26.0",
            ),
        ],
    )
