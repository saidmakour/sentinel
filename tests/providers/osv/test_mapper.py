from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.providers.osv.mapper import OSVMapper
from sentinel.providers.osv.models import OSVAffected
from sentinel.providers.osv.models import OSVEvent
from sentinel.providers.osv.models import OSVRange
from sentinel.providers.osv.models import OSVResponse
from sentinel.providers.osv.models import OSVSeverity
from sentinel.providers.osv.models import OSVVulnerability


def test_map_single_vulnerability() -> None:
    dependency = ScannedDependency(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI.value,
        source="requirements.txt",
        priority=10,
    )

    response = OSVResponse(
        vulns=[
            OSVVulnerability(
                identifier="GHSA-xxxx",
                aliases=["GHSA-xxxx-A"],
                summary="Test vulnerability",
                severity=[
                    OSVSeverity(
                        type="CVSS_V3",
                        score="9.8",
                    )
                ],
            )
        ]
    )

    mapper = OSVMapper()

    results = mapper.map(
        dependency,
        response,
    )

    assert len(results) == 1

    result = results[0]

    assert result.identifier == "GHSA-xxxx"
    assert result.aliases == ["GHSA-xxxx-A"]
    assert result.dependency_name == "requests"
    assert result.dependency_version == "2.31.0"
    assert result.ecosystem == Ecosystem.PYPI.value
    assert result.sources == [Provider.OSV]
    assert result.cvss == 9.8
    assert result.severity == Severity.CRITICAL
    assert result.summary == "Test vulnerability"
    assert result.remediation is not None
    assert result.remediation.rules == []


def test_map_remediation_rules() -> None:
    dependency = ScannedDependency(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI.value,
        source="requirements.txt",
        priority=10,
    )

    mapper = OSVMapper()

    response = OSVResponse(
        vulns=[
            OSVVulnerability(
                identifier="CVE-2026-0001",
                aliases=[],
                summary="test",
                severity=[
                    OSVSeverity(
                        type="CVSS_V3",
                        score="9.8",
                    )
                ],
                affected=[
                    OSVAffected(
                        package_name="requests",
                        ranges=[
                            OSVRange(
                                type="ECOSYSTEM",
                                events=[
                                    OSVEvent(
                                        introduced="0",
                                        fixed="2.32.0",
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            )
        ]
    )

    result = mapper.map(
        dependency,
        response,
    )

    assert len(result) == 1

    finding = result[0]

    assert finding.remediation is not None
    assert finding.remediation.rules == [
        RemediationRule(
            introduced="0",
            fixed="2.32.0",
        ),
    ]
