from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.providers.github.mapper import GitHubAdvisoryMapper
from sentinel.providers.github.models import GitHubAdvisory
from sentinel.providers.github.models import GitHubCVSS
from sentinel.providers.github.models import GitHubCVSSSeverities
from sentinel.providers.github.models import GitHubIdentifier
from sentinel.providers.github.models import GitHubPackage
from sentinel.providers.github.models import GitHubVulnerability


def create_dependency() -> ScannedDependency:
    return ScannedDependency(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
    )


def create_advisory(
    *,
    cve_id: str | None = "CVE-2026-1234",
    severity: str = "high",
) -> GitHubAdvisory:
    return GitHubAdvisory(
        ghsa_id="GHSA-abcd-1234-efgh",
        summary="Test vulnerability",
        description="Test description",
        severity=severity,
        cve_id=cve_id,
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
    )


def test_map_advisory_with_cve() -> None:
    mapper = GitHubAdvisoryMapper()

    result = mapper.map(
        create_dependency(),
        [create_advisory()],
    )

    assert len(result) == 1

    vulnerability = result[0]

    assert vulnerability.dependency_name == "requests"
    assert vulnerability.dependency_version == "2.31.0"
    assert vulnerability.ecosystem == Ecosystem.PYPI
    assert vulnerability.identifier == "CVE-2026-1234"
    assert vulnerability.summary == "Test vulnerability"
    assert vulnerability.severity == Severity.HIGH
    assert vulnerability.sources == [Provider.GITHUB_ADVISORY]


def test_map_advisory_without_cve_uses_ghsa() -> None:
    mapper = GitHubAdvisoryMapper()

    advisory = create_advisory(
        cve_id=None,
    )

    result = mapper.map(
        create_dependency(),
        [advisory],
    )

    assert len(result) == 1
    assert result[0].identifier == "GHSA-abcd-1234-efgh"


def test_map_builds_unique_aliases() -> None:
    mapper = GitHubAdvisoryMapper()

    advisory = create_advisory()

    advisory.identifiers.extend(
        [
            GitHubIdentifier(
                type="CVE",
                value="CVE-2026-1234",
            ),
            GitHubIdentifier(
                type="GHSA",
                value="GHSA-abcd-1234-efgh",
            ),
            GitHubIdentifier(
                type="OTHER",
                value="OTHER-1234",
            ),
        ],
    )

    result = mapper.map(
        create_dependency(),
        [advisory],
    )

    assert result[0].aliases == [
        "GHSA-abcd-1234-efgh",
        "CVE-2026-1234",
        "OTHER-1234",
    ]


def test_map_uses_highest_cvss_score() -> None:
    mapper = GitHubAdvisoryMapper()

    advisory = create_advisory()

    advisory.cvss = GitHubCVSS(
        score=7.5,
    )
    advisory.cvss_severities = GitHubCVSSSeverities(
        cvss_v3=GitHubCVSS(
            score=8.1,
        ),
        cvss_v4=GitHubCVSS(
            score=9.2,
        ),
    )

    result = mapper.map(
        create_dependency(),
        [advisory],
    )

    assert result[0].cvss == 9.2


def test_map_uses_top_level_cvss_when_other_scores_are_missing() -> None:
    mapper = GitHubAdvisoryMapper()

    advisory = create_advisory()

    advisory.cvss = GitHubCVSS(
        score=7.5,
    )

    result = mapper.map(
        create_dependency(),
        [advisory],
    )

    assert result[0].cvss == 7.5


def test_map_without_cvss() -> None:
    mapper = GitHubAdvisoryMapper()

    result = mapper.map(
        create_dependency(),
        [create_advisory()],
    )

    assert result[0].cvss is None


def test_map_fixed_versions() -> None:
    mapper = GitHubAdvisoryMapper()

    advisory = create_advisory()

    advisory.vulnerabilities.extend(
        [
            GitHubVulnerability(
                package=GitHubPackage(
                    ecosystem="pip",
                    name="requests",
                ),
                vulnerable_version_range="<2.30.0",
                first_patched_version="2.30.0",
            ),
            GitHubVulnerability(
                package=GitHubPackage(
                    ecosystem="pip",
                    name="requests",
                ),
                vulnerable_version_range="<2.32.0",
                first_patched_version="2.32.0",
            ),
        ],
    )

    result = mapper.map(
        create_dependency(),
        [advisory],
    )

    assert result[0].fixed_versions == [
        "2.32.0",
        "2.30.0",
    ]


def test_map_removes_duplicate_fixed_versions() -> None:
    mapper = GitHubAdvisoryMapper()

    advisory = create_advisory()

    advisory.vulnerabilities.append(
        GitHubVulnerability(
            package=GitHubPackage(
                ecosystem="pip",
                name="requests",
            ),
            vulnerable_version_range="<2.32.0",
            first_patched_version="2.32.0",
        ),
    )

    result = mapper.map(
        create_dependency(),
        [advisory],
    )

    assert result[0].fixed_versions == ["2.32.0"]


def test_map_ignores_vulnerabilities_without_fixed_version() -> None:
    mapper = GitHubAdvisoryMapper()

    advisory = create_advisory()

    advisory.vulnerabilities.append(
        GitHubVulnerability(
            package=GitHubPackage(
                ecosystem="pip",
                name="requests",
            ),
            vulnerable_version_range="<2.30.0",
            first_patched_version=None,
        ),
    )

    result = mapper.map(
        create_dependency(),
        [advisory],
    )

    assert result[0].fixed_versions == ["2.32.0"]


def test_map_severity_critical() -> None:
    mapper = GitHubAdvisoryMapper()

    result = mapper.map(
        create_dependency(),
        [create_advisory(severity="critical")],
    )

    assert result[0].severity == Severity.CRITICAL


def test_map_severity_high() -> None:
    mapper = GitHubAdvisoryMapper()

    result = mapper.map(
        create_dependency(),
        [create_advisory(severity="high")],
    )

    assert result[0].severity == Severity.HIGH


def test_map_severity_moderate() -> None:
    mapper = GitHubAdvisoryMapper()

    result = mapper.map(
        create_dependency(),
        [create_advisory(severity="moderate")],
    )

    assert result[0].severity == Severity.MEDIUM


def test_map_severity_medium() -> None:
    mapper = GitHubAdvisoryMapper()

    result = mapper.map(
        create_dependency(),
        [create_advisory(severity="medium")],
    )

    assert result[0].severity == Severity.MEDIUM


def test_map_severity_low() -> None:
    mapper = GitHubAdvisoryMapper()

    result = mapper.map(
        create_dependency(),
        [create_advisory(severity="low")],
    )

    assert result[0].severity == Severity.LOW


def test_map_unknown_severity() -> None:
    mapper = GitHubAdvisoryMapper()

    result = mapper.map(
        create_dependency(),
        [create_advisory(severity="unknown")],
    )

    assert result[0].severity == Severity.UNKNOWN


def test_map_empty_advisories() -> None:
    mapper = GitHubAdvisoryMapper()

    result = mapper.map(
        create_dependency(),
        [],
    )

    assert result == []


def test_map_multiple_advisories() -> None:
    mapper = GitHubAdvisoryMapper()

    first = create_advisory()
    second = create_advisory(
        cve_id="CVE-2026-5678",
        severity="critical",
    )
    second.ghsa_id = "GHSA-wxyz-5678-abcd"

    result = mapper.map(
        create_dependency(),
        [first, second],
    )

    assert len(result) == 2
    assert result[0].identifier == "CVE-2026-1234"
    assert result[0].severity == Severity.HIGH
    assert result[1].identifier == "CVE-2026-5678"
    assert result[1].severity == Severity.CRITICAL


def test_map_remediation() -> None:
    mapper = GitHubAdvisoryMapper()

    result = mapper.map(
        create_dependency(),
        [create_advisory()],
    )

    assert result[0].remediation is not None
    assert result[0].remediation.rules == [
        RemediationRule(
            affected_range="<2.32.0",
            fixed="2.32.0",
        ),
    ]


def test_map_multiple_remediation_rules() -> None:
    mapper = GitHubAdvisoryMapper()

    advisory = create_advisory()

    advisory.vulnerabilities.extend(
        [
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

    result = mapper.map(
        create_dependency(),
        [advisory],
    )

    assert result[0].remediation is not None
    assert result[0].remediation.rules == [
        RemediationRule(
            affected_range="<2.32.0",
            fixed="2.32.0",
        ),
        RemediationRule(
            affected_range=">=2.0.0,<2.20.0",
            fixed="2.20.0",
        ),
        RemediationRule(
            affected_range=">=2.25.0,<2.26.0",
            fixed="2.26.0",
        ),
    ]
