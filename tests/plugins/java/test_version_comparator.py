from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.plugins.java.version_comparator import JavaVersionComparator


def test_determine_status_returns_unknown_without_rules() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[],
    )

    assert (
        comparator.determine_status(
            installed_version="17.0.1",
            remediation=remediation,
        )
        == VulnerabilityStatus.UNKNOWN
    )


def test_determine_status_returns_unknown_for_invalid_version() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="17.0.0",
                fixed="17.0.5",
                affected_range=None,
            ),
        ],
    )

    assert (
        comparator.determine_status(
            installed_version="invalid",
            remediation=remediation,
        )
        == VulnerabilityStatus.UNKNOWN
    )


def test_determine_status_returns_open_when_version_is_before_fixed() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="17.0.0",
                fixed="17.0.5",
                affected_range=None,
            ),
        ],
    )

    assert (
        comparator.determine_status(
            installed_version="17.0.3",
            remediation=remediation,
        )
        == VulnerabilityStatus.OPEN
    )


def test_determine_status_returns_resolved_when_version_is_fixed() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="17.0.0",
                fixed="17.0.5",
                affected_range=None,
            ),
        ],
    )

    assert (
        comparator.determine_status(
            installed_version="17.0.5",
            remediation=remediation,
        )
        == VulnerabilityStatus.RESOLVED
    )


def test_determine_status_returns_resolved_when_version_is_after_fixed() -> (
    None
):
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="17.0.0",
                fixed="17.0.5",
                affected_range=None,
            ),
        ],
    )

    assert (
        comparator.determine_status(
            installed_version="21.0.0",
            remediation=remediation,
        )
        == VulnerabilityStatus.RESOLVED
    )


def test_determine_status_supports_legacy_java_version() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="8",
                fixed="8.0.1",
                affected_range=None,
            ),
        ],
    )

    assert (
        comparator.determine_status(
            installed_version="1.8",
            remediation=remediation,
        )
        == VulnerabilityStatus.OPEN
    )


def test_determine_status_supports_affected_range() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced=None,
                fixed=None,
                affected_range=">=17.0.0 <17.0.5",
            ),
        ],
    )

    assert (
        comparator.determine_status(
            installed_version="17.0.3",
            remediation=remediation,
        )
        == VulnerabilityStatus.OPEN
    )


def test_determine_status_returns_resolved_outside_affected_range() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced=None,
                fixed=None,
                affected_range=">=17.0.0 <17.0.5",
            ),
        ],
    )

    assert (
        comparator.determine_status(
            installed_version="17.0.5",
            remediation=remediation,
        )
        == VulnerabilityStatus.RESOLVED
    )


def test_determine_status_supports_multiple_constraints() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced=None,
                fixed=None,
                affected_range=">=17.0.0,<17.0.5",
            ),
        ],
    )

    assert (
        comparator.determine_status(
            installed_version="17.0.2",
            remediation=remediation,
        )
        == VulnerabilityStatus.OPEN
    )


def test_determine_status_ignores_invalid_rules() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="invalid",
                fixed="17.0.5",
                affected_range=None,
            ),
            RemediationRule(
                introduced="17.0.0",
                fixed="17.0.5",
                affected_range=None,
            ),
        ],
    )

    assert (
        comparator.determine_status(
            installed_version="17.0.3",
            remediation=remediation,
        )
        == VulnerabilityStatus.OPEN
    )


def test_compare_versions_returns_negative_when_first_is_lower() -> None:
    comparator = JavaVersionComparator()

    assert (
        comparator.compare_versions(
            "17.0.1",
            "17.0.2",
        )
        < 0
    )


def test_compare_versions_returns_positive_when_first_is_higher() -> None:
    comparator = JavaVersionComparator()

    assert (
        comparator.compare_versions(
            "17.0.2",
            "17.0.1",
        )
        > 0
    )


def test_compare_versions_returns_zero_for_equal_versions() -> None:
    comparator = JavaVersionComparator()

    assert (
        comparator.compare_versions(
            "17.0.1",
            "17.0.1",
        )
        == 0
    )


def test_compare_versions_supports_legacy_java_versions() -> None:
    comparator = JavaVersionComparator()

    assert (
        comparator.compare_versions(
            "1.8",
            "8",
        )
        == 0
    )


def test_compare_versions_ignores_build_metadata() -> None:
    comparator = JavaVersionComparator()

    assert (
        comparator.compare_versions(
            "17.0.10+7",
            "17.0.10",
        )
        == 0
    )


def test_compare_versions_ignores_early_access_suffix() -> None:
    comparator = JavaVersionComparator()

    assert (
        comparator.compare_versions(
            "21.0.1-ea",
            "21.0.1",
        )
        == 0
    )


def test_recommended_version_returns_fixed_version() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="17.0.0",
                fixed="17.0.5",
                affected_range=None,
            ),
        ],
    )

    assert (
        comparator.recommended_version(
            installed_version="17.0.2",
            remediation=remediation,
        )
        == "17.0.5"
    )


def test_recommended_version_returns_lowest_fixed_version() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="17.0.0",
                fixed="17.0.5",
                affected_range=None,
            ),
            RemediationRule(
                introduced="17.0.5",
                fixed="17.0.8",
                affected_range=None,
            ),
        ],
    )

    assert (
        comparator.recommended_version(
            installed_version="17.0.2",
            remediation=remediation,
        )
        == "17.0.5"
    )


def test_recommended_version_returns_none_when_no_fixed_version() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="17.0.0",
                fixed=None,
                affected_range="<17.0.5",
            ),
        ],
    )

    assert (
        comparator.recommended_version(
            installed_version="17.0.2",
            remediation=remediation,
        )
        is None
    )


def test_recommended_version_returns_none_for_invalid_installed_version() -> (
    None
):
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="17.0.0",
                fixed="17.0.5",
                affected_range=None,
            ),
        ],
    )

    assert (
        comparator.recommended_version(
            installed_version="invalid",
            remediation=remediation,
        )
        is None
    )


def test_recommended_version_ignores_fixed_versions_lower_than_installed() -> (
    None
):
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="17.0.0",
                fixed="17.0.2",
                affected_range=None,
            ),
        ],
    )

    assert (
        comparator.recommended_version(
            installed_version="17.0.5",
            remediation=remediation,
        )
        is None
    )


def test_recommended_version_uses_matching_rule() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="8",
                fixed="11",
            ),
            RemediationRule(
                introduced="17",
                fixed="21",
            ),
        ],
    )

    result = comparator.recommended_version(
        installed_version="17.0.5",
        remediation=remediation,
    )

    assert result == "21"


def test_recommended_version_uses_matching_affected_range() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                affected_range=">=8 <11",
                fixed="11",
            ),
            RemediationRule(
                affected_range=">=17 <21",
                fixed="21",
            ),
        ],
    )

    result = comparator.recommended_version(
        installed_version="17.0.5",
        remediation=remediation,
    )

    assert result == "21"


def test_recommended_version_returns_none_for_open_ended_rule() -> None:
    comparator = JavaVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="17",
            ),
        ],
    )

    result = comparator.recommended_version(
        installed_version="17.0.5",
        remediation=remediation,
    )

    assert result is None
