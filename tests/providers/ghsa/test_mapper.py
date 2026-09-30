from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.providers.ghsa.mapper import GHSAMapper
from sentinel.providers.ghsa.models import GHSACVSS
from sentinel.providers.ghsa.models import GHSAPackage
from sentinel.providers.ghsa.models import GHSAResponse
from sentinel.providers.ghsa.models import GHSAVulnerability


def create_dependency() -> ScannedDependency:
    return ScannedDependency(
        name="requests",
        version="2.32.0",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
    )


def test_mapper_can_be_created() -> None:
    mapper = GHSAMapper()

    assert mapper is not None


def test_map_empty_response() -> None:
    mapper = GHSAMapper()

    result = mapper.map(
        create_dependency(),
        GHSAResponse(
            vulnerabilities=[],
        ),
    )

    assert result == []


def test_map_single_vulnerability() -> None:
    mapper = GHSAMapper()

    response = GHSAResponse(
        vulnerabilities=[
            GHSAVulnerability(
                ghsa_id="GHSA-1111",
                cve_id="CVE-2026-0001",
                summary="Example",
                severity="HIGH",
                identifiers=[],
                description="test GHSA",
            )
        ]
    )

    findings = mapper.map(
        create_dependency(),
        response,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.identifier == "CVE-2026-0001"
    assert finding.sources == [
        Provider.GHSA,
    ]
    assert finding.summary == "Example"
    assert finding.severity == Severity.HIGH
    assert finding.cvss is None


def test_map_uses_ghsa_identifier_when_cve_is_missing() -> None:
    mapper = GHSAMapper()

    response = GHSAResponse(
        vulnerabilities=[
            GHSAVulnerability(
                ghsa_id="GHSA-2222",
                cve_id=None,
                summary="Example",
                severity="LOW",
                identifiers=[],
                description="test GHSA",
            )
        ]
    )

    findings = mapper.map(
        create_dependency(),
        response,
    )

    assert findings[0].identifier == "GHSA-2222"


def test_map_cvss_score() -> None:
    mapper = GHSAMapper()

    response = GHSAResponse(
        vulnerabilities=[
            GHSAVulnerability(
                ghsa_id="GHSA-3333",
                cve_id=None,
                summary="Example",
                description="",
                severity="CRITICAL",
                identifiers=[],
                cvss_v4=GHSACVSS(
                    score=9.8,
                    vector_string="CVSS:4.0/...",
                ),
            )
        ]
    )

    findings = mapper.map(
        create_dependency(),
        response,
    )

    assert findings[0].cvss == 9.8


def test_severity_high() -> None:
    mapper = GHSAMapper()

    assert (
        mapper._severity(
            "HIGH",
        )
        == Severity.HIGH
    )


def test_severity_unknown() -> None:
    mapper = GHSAMapper()

    assert (
        mapper._severity(
            "INVALID",
        )
        == Severity.UNKNOWN
    )


def test_map_multiple_vulnerabilities() -> None:
    mapper = GHSAMapper()

    response = GHSAResponse(
        vulnerabilities=[
            GHSAVulnerability(
                ghsa_id="GHSA-1",
                cve_id=None,
                summary="One",
                severity="LOW",
                identifiers=[],
                description="",
            ),
            GHSAVulnerability(
                ghsa_id="GHSA-2",
                cve_id=None,
                summary="Two",
                severity="HIGH",
                identifiers=[],
                description="",
            ),
        ]
    )

    findings = mapper.map(
        create_dependency(),
        response,
    )

    assert len(findings) == 2


def test_map_remediation() -> None:
    mapper = GHSAMapper()

    response = GHSAResponse(
        vulnerabilities=[
            GHSAVulnerability(
                ghsa_id="GHSA-3333",
                cve_id="CVE-2026-0001",
                summary="Example",
                description="",
                severity="HIGH",
                identifiers=[],
                package=GHSAPackage(
                    ecosystem="pip",
                    name="requests",
                    first_patched_version="2.32.3",
                    vulnerable_version_range="<2.32.3",
                ),
            )
        ]
    )

    findings = mapper.map(
        create_dependency(),
        response,
    )

    remediation = findings[0].remediation.rules[0]

    assert remediation is not None
    assert remediation.fixed == "2.32.3"
    assert remediation.affected_range == "<2.32.3"
