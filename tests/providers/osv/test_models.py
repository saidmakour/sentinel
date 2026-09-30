from sentinel.dto.remediation_info import RemediationRule
from sentinel.providers.osv.client import OSVClient
from sentinel.providers.osv.models import OSVAffected
from sentinel.providers.osv.models import OSVEvent
from sentinel.providers.osv.models import OSVRange
from sentinel.providers.osv.models import OSVSeverity
from sentinel.providers.osv.models import OSVVulnerability


def test_cvss_property_returns_none() -> None:
    vuln = OSVVulnerability(
        identifier="CVE",
        aliases=[],
        summary="",
        severity=[],
    )

    assert vuln.cvss is None


def test_cvss_property_returns_float() -> None:
    vuln = OSVVulnerability(
        identifier="CVE",
        aliases=[],
        summary="",
        severity=[
            OSVSeverity(
                type="CVSS_V3",
                score="8.6",
            )
        ],
    )

    assert vuln.cvss == 8.6


def test_cvss_property_returns_none_for_invalid_value() -> None:
    vuln = OSVVulnerability(
        identifier="CVE",
        aliases=[],
        summary="",
        severity=[
            OSVSeverity(
                type="CVSS_V3",
                score="invalid",
            )
        ],
    )

    assert vuln.cvss is None


def test_parse_response() -> None:
    client = OSVClient()

    response = client._parse_response(
        {
            "vulns": [
                {
                    "id": "CVE-2024-0001",
                    "summary": "Test vulnerability",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "9.8",
                        }
                    ],
                }
            ]
        }
    )

    assert len(response.vulns) == 1

    vuln = response.vulns[0]

    assert vuln.identifier == "CVE-2024-0001"
    assert vuln.summary == "Test vulnerability"
    assert vuln.cvss == 9.8


def test_remediation_pairs_introduced_and_fixed_events() -> None:
    vulnerability = OSVVulnerability(
        identifier="GHSA-test",
        aliases=[],
        summary="Test vulnerability",
        severity=[],
        affected=[
            OSVAffected(
                package_name="requests",
                ranges=[
                    OSVRange(
                        type="SEMVER",
                        events=[
                            OSVEvent(introduced="1.0.0"),
                            OSVEvent(fixed="1.5.0"),
                            OSVEvent(introduced="2.0.0"),
                            OSVEvent(fixed="2.3.0"),
                        ],
                    ),
                ],
            ),
        ],
    )

    remediation = vulnerability.remediation

    assert len(remediation.rules) == 2

    assert remediation.rules[0] == RemediationRule(
        introduced="1.0.0",
        fixed="1.5.0",
    )
    assert remediation.rules[1] == RemediationRule(
        introduced="2.0.0",
        fixed="2.3.0",
    )
