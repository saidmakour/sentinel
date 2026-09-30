from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.plugins.php.version_comparator import PHPVersionComparator


def make_remediation(
    *,
    introduced: str | None = None,
    fixed: str | None = None,
    affected_range: str | None = None,
) -> RemediationInfo:
    return RemediationInfo(
        rules=[
            RemediationRule(
                introduced=introduced,
                fixed=fixed,
                affected_range=affected_range,
            ),
        ],
    )


def test_version_before_fixed_version_is_open() -> None:
    comparator = PHPVersionComparator()

    result = comparator.determine_status(
        "8.2.0",
        make_remediation(
            fixed="8.2.5",
        ),
    )

    assert result == VulnerabilityStatus.OPEN


def test_version_at_fixed_version_is_resolved() -> None:
    comparator = PHPVersionComparator()

    result = comparator.determine_status(
        "8.2.5",
        make_remediation(
            fixed="8.2.5",
        ),
    )

    assert result == VulnerabilityStatus.RESOLVED


def test_version_after_fixed_version_is_resolved() -> None:
    comparator = PHPVersionComparator()

    result = comparator.determine_status(
        "8.2.6",
        make_remediation(
            fixed="8.2.5",
        ),
    )

    assert result == VulnerabilityStatus.RESOLVED


def test_affected_range() -> None:
    comparator = PHPVersionComparator()

    result = comparator.determine_status(
        "8.2.3",
        make_remediation(
            affected_range=">=8.2.0 <8.2.5",
        ),
    )

    assert result == VulnerabilityStatus.OPEN


def test_affected_range_outside_range() -> None:
    comparator = PHPVersionComparator()

    result = comparator.determine_status(
        "8.2.5",
        make_remediation(
            affected_range=">=8.2.0 <8.2.5",
        ),
    )

    assert result == VulnerabilityStatus.RESOLVED


def test_caret_constraint() -> None:
    comparator = PHPVersionComparator()

    result = comparator.determine_status(
        "2.5.0",
        make_remediation(
            affected_range="^2.0",
        ),
    )

    assert result == VulnerabilityStatus.OPEN


def test_caret_constraint_outside_range() -> None:
    comparator = PHPVersionComparator()

    result = comparator.determine_status(
        "3.0.0",
        make_remediation(
            affected_range="^2.0",
        ),
    )

    assert result == VulnerabilityStatus.RESOLVED


def test_tilde_constraint() -> None:
    comparator = PHPVersionComparator()

    result = comparator.determine_status(
        "8.2.4",
        make_remediation(
            affected_range="~8.2",
        ),
    )

    assert result == VulnerabilityStatus.OPEN


def test_invalid_installed_version() -> None:
    comparator = PHPVersionComparator()

    result = comparator.determine_status(
        "not-a-version",
        make_remediation(
            fixed="8.2.5",
        ),
    )

    assert result == VulnerabilityStatus.UNKNOWN


def test_empty_remediation() -> None:
    comparator = PHPVersionComparator()

    result = comparator.determine_status(
        "8.2.0",
        RemediationInfo(
            rules=[],
        ),
    )

    assert result == VulnerabilityStatus.UNKNOWN


def test_compare_versions_returns_negative_when_first_is_lower() -> None:
    comparator = PHPVersionComparator()

    assert (
        comparator.compare_versions(
            "1.9.0",
            "1.10.0",
        )
        < 0
    )


def test_compare_versions_returns_positive_when_first_is_higher() -> None:
    comparator = PHPVersionComparator()

    assert (
        comparator.compare_versions(
            "1.10.0",
            "1.9.0",
        )
        > 0
    )


def test_compare_versions_returns_zero_for_equal_versions() -> None:
    comparator = PHPVersionComparator()

    assert (
        comparator.compare_versions(
            "1.10.0",
            "1.10.0",
        )
        == 0
    )


def test_compare_versions_accepts_leading_v() -> None:
    comparator = PHPVersionComparator()

    assert (
        comparator.compare_versions(
            "v1.2.3",
            "1.2.3",
        )
        == 0
    )


def test_recommended_version_returns_fixed_version() -> None:
    comparator = PHPVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="1.0.0",
                fixed="1.2.3",
                affected_range="<1.2.3",
            ),
        ],
    )

    assert (
        comparator.recommended_version(
            installed_version="1.2.0",
            remediation=remediation,
        )
        == "1.2.3"
    )


def test_recommended_version_returns_lowest_fixed_version_above_installed() -> (
    None
):
    comparator = PHPVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="1.0.0",
                fixed="1.2.3",
                affected_range="<1.2.3",
            ),
            RemediationRule(
                introduced="1.2.3",
                fixed="1.4.0",
                affected_range="<1.4.0",
            ),
        ],
    )

    assert (
        comparator.recommended_version(
            installed_version="1.2.0",
            remediation=remediation,
        )
        == "1.2.3"
    )


def test_recommended_version_returns_none_without_fixed_version() -> None:
    comparator = PHPVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="1.0.0",
                fixed=None,
                affected_range="<1.2.0",
            ),
        ],
    )

    assert (
        comparator.recommended_version(
            installed_version="1.1.0",
            remediation=remediation,
        )
        is None
    )


def test_recommended_version_returns_none_for_invalid_installed_version() -> (
    None
):
    comparator = PHPVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="1.0.0",
                fixed="1.2.3",
                affected_range="<1.2.3",
            ),
        ],
    )

    assert (
        comparator.recommended_version(
            installed_version="not-a-version",
            remediation=remediation,
        )
        is None
    )


def test_determine_status_supports_caret_constraint() -> None:
    comparator = PHPVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced=None,
                fixed=None,
                affected_range="^1.2",
            ),
        ],
    )

    assert (
        comparator.determine_status(
            installed_version="1.2.5",
            remediation=remediation,
        )
        == VulnerabilityStatus.OPEN
    )


def test_determine_status_resolves_version_outside_caret_constraint() -> None:
    comparator = PHPVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced=None,
                fixed=None,
                affected_range="^1.2",
            ),
        ],
    )

    assert (
        comparator.determine_status(
            installed_version="2.0.0",
            remediation=remediation,
        )
        == VulnerabilityStatus.RESOLVED
    )


def test_recommended_version_uses_matching_rule() -> None:
    comparator = PHPVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="1.0.0",
                fixed="2.0.0",
            ),
            RemediationRule(
                introduced="3.0.0",
                fixed="4.0.0",
            ),
        ],
    )

    result = comparator.recommended_version(
        installed_version="3.5.0",
        remediation=remediation,
    )

    assert result == "4.0.0"


def test_recommended_version_uses_matching_affected_range() -> None:
    comparator = PHPVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                affected_range=">=1.0.0 <2.0.0",
                fixed="2.0.0",
            ),
            RemediationRule(
                affected_range=">=3.0.0 <4.0.0",
                fixed="4.0.0",
            ),
        ],
    )

    result = comparator.recommended_version(
        installed_version="3.5.0",
        remediation=remediation,
    )

    assert result == "4.0.0"


def test_recommended_version_returns_none_for_open_ended_rule() -> None:
    comparator = PHPVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="2.0.0",
            ),
        ],
    )

    result = comparator.recommended_version(
        installed_version="2.5.0",
        remediation=remediation,
    )

    assert result is None
