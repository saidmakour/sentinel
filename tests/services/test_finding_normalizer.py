from datetime import datetime

from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.services.finding_normalizer import FindingNormalizer


def create_finding(
    *,
    dependency_name: str = "requests",
    dependency_version: str = "2.32.3",
    ecosystem: Ecosystem = Ecosystem.PYPI,
    identifier: str = "CVE-2026-0001",
    aliases: list[str] | None = None,
    sources: list[Provider] | None = None,
    severity: Severity = Severity.HIGH,
    cvss: float | None = 7.5,
    summary: str = "Test vulnerability",
    remediation: RemediationInfo | None = None,
    fixed_versions: list[str] | None = None,
    known_exploited: bool = False,
    kev_date_added: str | None = None,
    kev_vendor: str | None = None,
    kev_product: str | None = None,
    kev_required_action: str | None = None,
    kev_known_ransomware: bool | None = None,
    vulncheck_known_exploited: bool = False,
    vulncheck_date_added: datetime | None = None,
    vulncheck_cisa_date_added: datetime | None = None,
    vulncheck_due_date: datetime | None = None,
    vulncheck_vendor: str | None = None,
    vulncheck_product: str | None = None,
    vulncheck_required_action: str | None = None,
    vulncheck_known_ransomware: str | None = None,
    vulncheck_reported_exploited_by_canaries: bool = False,
    epss_score: float | None = None,
    epss_percentile: float | None = None,
) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        dependency_name=dependency_name,
        dependency_version=dependency_version,
        ecosystem=ecosystem,
        identifier=identifier,
        aliases=aliases or [],
        sources=sources or [],
        summary=summary,
        severity=severity,
        cvss=cvss,
        remediation=remediation,
        fixed_versions=fixed_versions or [],
        known_exploited=known_exploited,
        kev_date_added=kev_date_added,
        kev_vendor=kev_vendor,
        kev_product=kev_product,
        kev_required_action=kev_required_action,
        kev_known_ransomware=kev_known_ransomware,
        vulncheck_known_exploited=vulncheck_known_exploited,
        vulncheck_date_added=vulncheck_date_added,
        vulncheck_cisa_date_added=vulncheck_cisa_date_added,
        vulncheck_due_date=vulncheck_due_date,
        vulncheck_vendor=vulncheck_vendor,
        vulncheck_product=vulncheck_product,
        vulncheck_required_action=vulncheck_required_action,
        vulncheck_known_ransomware=vulncheck_known_ransomware,
        vulncheck_reported_exploited_by_canaries=(
            vulncheck_reported_exploited_by_canaries
        ),
        epss_score=epss_score,
        epss_percentile=epss_percentile,
    )


def test_normalizer_can_be_created() -> None:
    normalizer = FindingNormalizer()

    assert normalizer is not None


def test_normalize_empty_findings() -> None:
    normalizer = FindingNormalizer()

    result = normalizer.normalize([])

    assert result == []


def test_normalize_keeps_unique_findings() -> None:
    normalizer = FindingNormalizer()

    finding = create_finding()

    result = normalizer.normalize(
        [finding],
    )

    assert len(result) == 1
    assert result[0] == finding


def test_normalize_merges_duplicate_findings() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        sources=[Provider.OSV],
        severity=Severity.MEDIUM,
    )

    second = create_finding(
        sources=[Provider.NVD],
        severity=Severity.HIGH,
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert len(result) == 1

    merged = result[0]

    assert merged.identifier == "CVE-2026-0001"
    assert merged.sources == [
        Provider.OSV,
        Provider.NVD,
    ]

    assert merged.severity == Severity.HIGH


def test_normalize_does_not_merge_different_dependencies() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        dependency_name="requests",
    )

    second = create_finding(
        dependency_name="flask",
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert len(result) == 2


def test_normalize_does_not_merge_different_versions() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        dependency_version="2.31.0",
    )

    second = create_finding(
        dependency_version="2.32.3",
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert len(result) == 2


def test_normalize_does_not_merge_different_identifiers() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        identifier="CVE-2026-0001",
    )

    second = create_finding(
        identifier="CVE-2026-0002",
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert len(result) == 2


def test_merge_keeps_unique_sources() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        sources=[
            Provider.OSV,
            Provider.NVD,
        ],
    )

    second = create_finding(
        sources=[
            Provider.NVD,
        ],
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert result[0].sources == [
        Provider.OSV,
        Provider.NVD,
    ]


def test_merge_uses_highest_cvss() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        cvss=5.0,
    )

    second = create_finding(
        cvss=9.8,
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert result[0].cvss == 9.8


def test_merge_cvss_returns_none_when_all_scores_are_none() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        cvss=None,
    )

    second = create_finding(
        cvss=None,
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert result[0].cvss is None


def test_merge_uses_highest_severity() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        severity=Severity.LOW,
    )

    second = create_finding(
        severity=Severity.CRITICAL,
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert result[0].severity == Severity.CRITICAL


def test_merge_defaults_to_unknown_when_no_findings() -> None:
    normalizer = FindingNormalizer()

    result = normalizer._merge_severity([])

    assert result == Severity.UNKNOWN


def test_merge_known_exploited_when_any_finding_is_exploited() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        known_exploited=False,
    )

    second = create_finding(
        known_exploited=True,
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert result[0].known_exploited is True


def test_merge_known_exploited_is_false_when_none_are_exploited() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        known_exploited=False,
    )

    second = create_finding(
        known_exploited=False,
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert result[0].known_exploited is False


def test_merge_kev_uses_first_non_none_value() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        kev_date_added=None,
        kev_vendor=None,
        kev_product=None,
        kev_required_action=None,
        kev_known_ransomware=None,
    )

    second = create_finding(
        kev_date_added="2026-01-01",
        kev_vendor="Vendor",
        kev_product="Product",
        kev_required_action="Update",
        kev_known_ransomware=True,
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    merged = result[0]

    assert merged.kev_date_added == "2026-01-01"
    assert merged.kev_vendor == "Vendor"
    assert merged.kev_product == "Product"
    assert merged.kev_required_action == "Update"
    assert merged.kev_known_ransomware is True


def test_merge_kev_keeps_first_non_none_value() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        kev_vendor="First Vendor",
    )

    second = create_finding(
        kev_vendor="Second Vendor",
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert result[0].kev_vendor == "First Vendor"


def test_merge_vulncheck_kev_uses_first_non_none_value() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        vulncheck_known_exploited=False,
        vulncheck_date_added=None,
        vulncheck_cisa_date_added=None,
        vulncheck_due_date=None,
        vulncheck_vendor=None,
        vulncheck_product=None,
        vulncheck_required_action=None,
        vulncheck_known_ransomware=None,
        vulncheck_reported_exploited_by_canaries=False,
    )

    second = create_finding(
        vulncheck_known_exploited=True,
        vulncheck_date_added=datetime(2026, 2, 1),
        vulncheck_cisa_date_added=datetime(2026, 2, 2),
        vulncheck_due_date=datetime(2026, 3, 1),
        vulncheck_vendor="VulnCheck Vendor",
        vulncheck_product="VulnCheck Product",
        vulncheck_required_action="Apply the patch",
        vulncheck_known_ransomware="Known",
        vulncheck_reported_exploited_by_canaries=True,
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    merged = result[0]

    assert merged.vulncheck_known_exploited is True
    assert merged.vulncheck_date_added == datetime(2026, 2, 1)
    assert merged.vulncheck_cisa_date_added == datetime(2026, 2, 2)
    assert merged.vulncheck_due_date == datetime(2026, 3, 1)
    assert merged.vulncheck_vendor == "VulnCheck Vendor"
    assert merged.vulncheck_product == "VulnCheck Product"
    assert merged.vulncheck_required_action == "Apply the patch"
    assert merged.vulncheck_known_ransomware == "Known"
    assert merged.vulncheck_reported_exploited_by_canaries is True


def test_merge_epss_uses_highest_score_and_percentile() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        epss_score=0.4,
        epss_percentile=0.6,
    )

    second = create_finding(
        epss_score=0.9,
        epss_percentile=0.8,
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert result[0].epss_score == 0.9
    assert result[0].epss_percentile == 0.8


def test_merge_epss_returns_none_when_all_values_are_none() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        epss_score=None,
        epss_percentile=None,
    )

    second = create_finding(
        epss_score=None,
        epss_percentile=None,
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert result[0].epss_score is None
    assert result[0].epss_percentile is None


def test_merge_vulncheck_kev_keeps_first_non_none_value() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        vulncheck_known_exploited=True,
        vulncheck_date_added=datetime(2026, 2, 1),
        vulncheck_cisa_date_added=datetime(2026, 2, 2),
        vulncheck_due_date=datetime(2026, 3, 1),
        vulncheck_vendor="First Vendor",
        vulncheck_product="First Product",
        vulncheck_required_action="First Action",
        vulncheck_known_ransomware="First",
        vulncheck_reported_exploited_by_canaries=True,
    )

    second = create_finding(
        vulncheck_known_exploited=False,
        vulncheck_date_added=datetime(2026, 4, 1),
        vulncheck_cisa_date_added=datetime(2026, 4, 2),
        vulncheck_due_date=datetime(2026, 5, 1),
        vulncheck_vendor="Second Vendor",
        vulncheck_product="Second Product",
        vulncheck_required_action="Second Action",
        vulncheck_known_ransomware="Second",
        vulncheck_reported_exploited_by_canaries=False,
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    merged = result[0]

    assert merged.vulncheck_known_exploited is True
    assert merged.vulncheck_date_added == datetime(2026, 2, 1)
    assert merged.vulncheck_cisa_date_added == datetime(2026, 2, 2)
    assert merged.vulncheck_due_date == datetime(2026, 3, 1)
    assert merged.vulncheck_vendor == "First Vendor"
    assert merged.vulncheck_product == "First Product"
    assert merged.vulncheck_required_action == "First Action"
    assert merged.vulncheck_known_ransomware == "First"
    assert merged.vulncheck_reported_exploited_by_canaries is True


def test_merge_summary_uses_longest_summary() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        summary="Short",
    )

    second = create_finding(
        summary="This is a much longer vulnerability summary",
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert result[0].summary == ("This is a much longer vulnerability summary")


def test_merge_summary_returns_empty_string_when_all_summaries_are_empty() -> (
    None
):
    normalizer = FindingNormalizer()

    first = create_finding(
        summary="",
    )

    second = create_finding(
        summary="",
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert result[0].summary == ""


def test_merge_does_not_mutate_original_finding() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        sources=[Provider.OSV],
        severity=Severity.MEDIUM,
    )

    second = create_finding(
        sources=[Provider.NVD],
        severity=Severity.HIGH,
    )

    original_sources = list(first.sources)
    original_severity = first.severity

    normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert first.sources == original_sources
    assert first.severity == original_severity


def test_normalize_merges_cve_and_ghsa_alias() -> None:
    normalizer = FindingNormalizer()

    osv_finding = create_finding(
        identifier="GHSA-jfh8-c2jp-5v3q",
        aliases=["CVE-2021-44228"],
        sources=[Provider.OSV],
    )

    nvd_finding = create_finding(
        identifier="CVE-2021-44228",
        sources=[Provider.NVD],
    )

    result = normalizer.normalize(
        [
            osv_finding,
            nvd_finding,
        ],
    )

    assert len(result) == 1

    merged = result[0]

    assert merged.identifier == "CVE-2021-44228"
    assert merged.aliases == ["GHSA-jfh8-c2jp-5v3q"]
    assert merged.sources == [
        Provider.OSV,
        Provider.NVD,
    ]


def test_normalize_uses_identifier_when_no_cve_alias_exists() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        identifier="GHSA-aaaa-bbbb-cccc",
        aliases=[],
    )

    second = create_finding(
        identifier="GHSA-aaaa-bbbb-cccc",
        aliases=[],
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert len(result) == 1
    assert result[0].identifier == "GHSA-aaaa-bbbb-cccc"


def test_canonical_identifier_prefers_cve() -> None:
    normalizer = FindingNormalizer()

    finding = create_finding(
        identifier="GHSA-jfh8-c2jp-5v3q",
        aliases=[
            "OSV-2021-1234",
            "CVE-2021-44228",
        ],
    )

    result = normalizer.normalize(
        [finding],
    )

    assert len(result) == 1
    assert result[0].identifier == "CVE-2021-44228"


def test_merge_remediation_returns_none_when_missing() -> None:
    normalizer = FindingNormalizer()

    first = create_finding()
    second = create_finding()

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    assert result[0].remediation is None


def test_merge_remediation_keeps_all_distinct_rules() -> None:
    normalizer = FindingNormalizer()

    first = create_finding(
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    fixed="2.32.3",
                ),
            ],
        ),
    )

    second = create_finding(
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    fixed="2.32.5",
                ),
            ],
        ),
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    remediation = result[0].remediation

    assert remediation is not None
    assert remediation.rules == [
        RemediationRule(fixed="2.32.3"),
        RemediationRule(fixed="2.32.5"),
    ]


def test_normalizer_keeps_fixed_versions_for_status_calculation():
    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-0001",
        aliases=["GHSA-xxxx"],
        sources=[Provider.OSV],
        summary="test",
        severity=Severity.HIGH,
        cvss=7.5,
        fixed_versions=[
            "2.32.0",
        ],
    )

    result = FindingNormalizer().normalize(
        [finding],
    )

    assert result[0].fixed_versions == [
        "2.32.0",
    ]


def test_merge_remediation_deduplicates_rules() -> None:
    normalizer = FindingNormalizer()

    rule = RemediationRule(
        introduced="1.0.0",
        fixed="2.0.0",
        affected_range="<2.0.0",
    )

    first = create_finding(
        remediation=RemediationInfo(
            rules=[rule],
        ),
    )

    second = create_finding(
        remediation=RemediationInfo(
            rules=[rule],
        ),
    )

    result = normalizer.normalize(
        [
            first,
            second,
        ],
    )

    remediation = result[0].remediation

    assert remediation is not None
    assert remediation.rules == [rule]
