from datetime import UTC
from datetime import datetime
from unittest.mock import MagicMock

from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.models.finding import Finding
from sentinel.services.findings_service import FindingService


def create_finding(
    *,
    identifier: str = "CVE-2026-0001",
    aliases: list[str] | None = None,
    severity: str = "HIGH",
) -> Finding:
    return Finding(
        id=1,
        scan_id=10,
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        identifier=identifier,
        aliases=aliases or [],
        sources=["OSV"],
        summary="Test vulnerability",
        severity=severity,
        cvss=7.5,
        status=VulnerabilityStatus.UNKNOWN,
        remediation=None,
        fixed_versions=[],
        known_exploited=True,
        kev_date_added=datetime(
            2026,
            1,
            1,
            tzinfo=UTC,
        ),
        kev_vendor="Example Vendor",
        kev_product="Example Product",
        kev_required_action="Update to a patched version",
        kev_known_ransomware=True,
        vulncheck_known_exploited=True,
        vulncheck_date_added=datetime(
            2026,
            2,
            1,
            tzinfo=UTC,
        ),
        vulncheck_cisa_date_added=datetime(
            2026,
            2,
            2,
            tzinfo=UTC,
        ),
        vulncheck_due_date=datetime(
            2026,
            3,
            1,
            tzinfo=UTC,
        ),
        vulncheck_vendor="VulnCheck Vendor",
        vulncheck_product="VulnCheck Product",
        vulncheck_required_action="Apply the vendor patch",
        vulncheck_known_ransomware="Known",
        vulncheck_reported_exploited_by_canaries=True,
        epss_score=0.95,
        epss_percentile=0.99,
    )


def create_service(
    monkeypatch,
    *,
    findings: list[Finding] | None = None,
    normalizer: MagicMock | None = None,
) -> tuple[
    FindingService,
    MagicMock,
    MagicMock,
]:
    session = MagicMock()

    repository = MagicMock()

    repository.list_by_scan.return_value = (
        findings if findings is not None else []
    )

    monkeypatch.setattr(
        "sentinel.services.findings_service.FindingRepository",
        lambda session: repository,
    )

    if normalizer is None:
        normalizer = MagicMock()

    monkeypatch.setattr(
        "sentinel.services.findings_service.FindingNormalizer",
        lambda: normalizer,
    )

    service = FindingService(
        session,
    )

    return (
        service,
        repository,
        normalizer,
    )


def test_finding_service_can_be_created(
    monkeypatch,
) -> None:
    service, repository, normalizer = create_service(
        monkeypatch,
    )

    assert service is not None
    assert service.repository is repository
    assert service.normalizer is normalizer


def test_finding_service_uses_provided_normalizer(
    monkeypatch,
) -> None:
    normalizer = MagicMock()

    service, _, _ = create_service(
        monkeypatch,
        normalizer=normalizer,
    )

    assert service.normalizer is normalizer


def test_list_by_scan_loads_findings_from_repository(
    monkeypatch,
) -> None:
    finding = create_finding()

    service, repository, normalizer = create_service(
        monkeypatch,
        findings=[finding],
    )

    normalizer.normalize.return_value = []

    service.list_by_scan(
        scan_id=10,
    )

    repository.list_by_scan.assert_called_once_with(
        10,
    )


def test_list_by_scan_converts_findings(
    monkeypatch,
) -> None:
    finding = create_finding()

    service, _, normalizer = create_service(
        monkeypatch,
        findings=[finding],
    )

    normalizer.normalize.return_value = []

    service.list_by_scan(
        scan_id=10,
    )

    normalized_input = normalizer.normalize.call_args.args[0]

    assert len(normalized_input) == 1

    vulnerability = normalized_input[0]

    assert isinstance(
        vulnerability,
        VulnerabilityInfo,
    )

    assert vulnerability.identifier == ("CVE-2026-0001")


def test_list_by_scan_returns_empty_list_when_no_findings(
    monkeypatch,
) -> None:
    service, repository, normalizer = create_service(
        monkeypatch,
        findings=[],
    )

    normalizer.normalize.return_value = []

    result = service.list_by_scan(
        scan_id=10,
    )

    repository.list_by_scan.assert_called_once_with(
        10,
    )

    normalizer.normalize.assert_called_once_with(
        [],
    )

    assert result == []


def test_to_vulnerability_info_converts_finding(
    monkeypatch,
) -> None:
    service, _, _ = create_service(
        monkeypatch,
    )

    finding = create_finding()

    result = service._to_vulnerability_info(
        finding,
    )

    assert isinstance(
        result,
        VulnerabilityInfo,
    )

    assert result.dependency_name == "requests"
    assert result.dependency_version == "2.32.3"
    assert result.identifier == "CVE-2026-0001"
    assert result.sources == [Provider.OSV]
    assert result.summary == "Test vulnerability"
    assert result.severity == Severity.HIGH
    assert result.ecosystem == Ecosystem.PYPI
    assert result.cvss == 7.5

    assert result.remediation is None
    assert result.fixed_versions == []

    assert result.known_exploited is True
    assert result.kev_date_added == datetime(
        2026,
        1,
        1,
        tzinfo=UTC,
    )
    assert result.kev_vendor == "Example Vendor"
    assert result.kev_product == "Example Product"
    assert result.kev_required_action == ("Update to a patched version")
    assert result.kev_known_ransomware is True

    assert result.epss_score == 0.95
    assert result.epss_percentile == 0.99

    assert result.vulncheck_known_exploited is True

    assert result.vulncheck_date_added == datetime(
        2026,
        2,
        1,
    )
    assert result.vulncheck_cisa_date_added == datetime(
        2026,
        2,
        2,
    )
    assert result.vulncheck_due_date == datetime(
        2026,
        3,
        1,
    )

    assert result.vulncheck_vendor == "VulnCheck Vendor"
    assert result.vulncheck_product == "VulnCheck Product"
    assert result.vulncheck_required_action == ("Apply the vendor patch")
    assert result.vulncheck_known_ransomware == "Known"
    assert result.vulncheck_reported_exploited_by_canaries is True


def test_list_by_scan_normalizes_vulnerabilities(
    monkeypatch,
) -> None:
    finding = create_finding()

    service, _, normalizer = create_service(
        monkeypatch,
        findings=[finding],
    )

    normalized_result = [
        VulnerabilityInfo(
            dependency_name="requests",
            dependency_version="2.32.3",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-2026-0001",
            aliases=["CVE-2026-0001"],
            sources=[Provider.OSV],
            summary="Test vulnerability",
            severity=Severity.HIGH,
            cvss=7.5,
        ),
    ]

    normalizer.normalize.return_value = normalized_result

    result = service.list_by_scan(
        scan_id=10,
    )

    normalizer.normalize.assert_called_once()

    assert result == normalized_result


def test_to_vulnerability_info_converts_remediation(
    monkeypatch,
) -> None:
    service, _, _ = create_service(
        monkeypatch,
    )

    finding = create_finding()
    finding.remediation = {
        "rules": [
            {
                "introduced": "1.0.0",
                "fixed": "1.5.0",
                "affected_range": "<1.5.0",
            },
            {
                "introduced": "2.0.0",
                "fixed": "2.3.0",
                "affected_range": "<2.3.0",
            },
        ],
    }

    result = service._to_vulnerability_info(
        finding,
    )

    assert result.remediation is not None
    assert len(result.remediation.rules) == 2

    assert result.remediation.rules[0].introduced == "1.0.0"
    assert result.remediation.rules[0].fixed == "1.5.0"
    assert result.remediation.rules[0].affected_range == "<1.5.0"

    assert result.remediation.rules[1].introduced == "2.0.0"
    assert result.remediation.rules[1].fixed == "2.3.0"
    assert result.remediation.rules[1].affected_range == "<2.3.0"
