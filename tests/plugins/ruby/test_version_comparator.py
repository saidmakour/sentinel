from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.plugins.ruby.version_comparator import RubyVersionComparator


def _remediation(
    *rules: RemediationRule,
) -> RemediationInfo:
    return RemediationInfo(rules=list(rules))


def test_compare_versions() -> None:
    comparator = RubyVersionComparator()

    assert comparator.compare_versions("7.1.5", "7.1.5") == 0
    assert comparator.compare_versions("7.1.4", "7.1.5") == -1
    assert comparator.compare_versions("7.1.6", "7.1.5") == 1


def test_compare_versions_with_different_component_counts() -> None:
    comparator = RubyVersionComparator()

    assert comparator.compare_versions("7.1", "7.1.0") == -1
    assert comparator.compare_versions("7.1.0", "7.1") == 1


def test_compare_versions_with_v_prefix() -> None:
    comparator = RubyVersionComparator()

    assert comparator.compare_versions("v7.1.5", "7.1.5") == 0


def test_compare_versions_invalid_version() -> None:
    comparator = RubyVersionComparator()

    assert comparator.compare_versions("invalid", "7.1.5") == 0


def test_status_unknown_without_rules() -> None:
    comparator = RubyVersionComparator()

    remediation = RemediationInfo(rules=[])

    assert (
        comparator.determine_status("7.1.5", remediation)
        is VulnerabilityStatus.UNKNOWN
    )


def test_status_unknown_with_invalid_installed_version() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(fixed="7.1.5"),
    )

    assert (
        comparator.determine_status("invalid", remediation)
        is VulnerabilityStatus.UNKNOWN
    )


def test_fixed_version_resolves_vulnerability() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(fixed="7.1.5"),
    )

    assert (
        comparator.determine_status("7.1.5", remediation)
        is VulnerabilityStatus.RESOLVED
    )


def test_version_before_fixed_is_open() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(fixed="7.1.5"),
    )

    assert (
        comparator.determine_status("7.1.4", remediation)
        is VulnerabilityStatus.OPEN
    )


def test_introduced_version_before_range() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(
            introduced="7.1.0",
            fixed="7.1.5",
        ),
    )

    assert (
        comparator.determine_status("7.0.9", remediation)
        is VulnerabilityStatus.RESOLVED
    )


def test_introduced_and_fixed_range() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(
            introduced="7.1.0",
            fixed="7.1.5",
        ),
    )

    assert (
        comparator.determine_status("7.1.2", remediation)
        is VulnerabilityStatus.OPEN
    )


def test_affected_range_greater_than() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(
            affected_range=">= 7.1.0 < 7.1.5",
        ),
    )

    assert (
        comparator.determine_status("7.1.2", remediation)
        is VulnerabilityStatus.OPEN
    )

    assert (
        comparator.determine_status("7.1.5", remediation)
        is VulnerabilityStatus.RESOLVED
    )


def test_pessimistic_constraint_two_components() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(
            affected_range="~> 7.1",
        ),
    )

    assert (
        comparator.determine_status("7.0.9", remediation)
        is VulnerabilityStatus.RESOLVED
    )

    assert (
        comparator.determine_status("7.1.0", remediation)
        is VulnerabilityStatus.OPEN
    )

    assert (
        comparator.determine_status("7.1.9", remediation)
        is VulnerabilityStatus.OPEN
    )

    assert (
        comparator.determine_status("7.2.0", remediation)
        is VulnerabilityStatus.OPEN
    )

    assert (
        comparator.determine_status("8.0.0", remediation)
        is VulnerabilityStatus.RESOLVED
    )


def test_pessimistic_constraint_three_components() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(
            affected_range="~> 7.1.5",
        ),
    )

    assert (
        comparator.determine_status("7.1.4", remediation)
        is VulnerabilityStatus.RESOLVED
    )

    assert (
        comparator.determine_status("7.1.5", remediation)
        is VulnerabilityStatus.OPEN
    )

    assert (
        comparator.determine_status("7.1.9", remediation)
        is VulnerabilityStatus.OPEN
    )

    assert (
        comparator.determine_status("7.2.0", remediation)
        is VulnerabilityStatus.RESOLVED
    )


def test_multiple_constraints() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(
            affected_range=">= 7.1.0, < 7.1.5",
        ),
    )

    assert (
        comparator.determine_status("7.1.2", remediation)
        is VulnerabilityStatus.OPEN
    )

    assert (
        comparator.determine_status("7.1.5", remediation)
        is VulnerabilityStatus.RESOLVED
    )


def test_not_equal_constraint() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(
            affected_range="!= 7.1.5",
        ),
    )

    assert (
        comparator.determine_status("7.1.4", remediation)
        is VulnerabilityStatus.OPEN
    )

    assert (
        comparator.determine_status("7.1.5", remediation)
        is VulnerabilityStatus.RESOLVED
    )


def test_exact_constraint() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(
            affected_range="7.1.5",
        ),
    )

    assert (
        comparator.determine_status("7.1.5", remediation)
        is VulnerabilityStatus.OPEN
    )

    assert (
        comparator.determine_status("7.1.6", remediation)
        is VulnerabilityStatus.RESOLVED
    )


def test_recommended_version() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(fixed="7.1.5"),
        RemediationRule(fixed="7.2.0"),
        RemediationRule(fixed="8.0.0"),
    )

    assert comparator.recommended_version("7.1.2", remediation) == "7.1.5"


def test_recommended_version_ignores_lower_fixed_versions() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(fixed="7.0.9"),
        RemediationRule(fixed="7.1.5"),
    )

    assert comparator.recommended_version("7.1.2", remediation) == "7.1.5"


def test_recommended_version_without_candidate() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(fixed="7.1.5"),
    )

    assert comparator.recommended_version("7.2.0", remediation) is None


def test_invalid_remediation_rules_are_ignored() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(fixed="invalid"),
        RemediationRule(fixed="7.1.5"),
    )

    assert (
        comparator.determine_status("7.1.2", remediation)
        is VulnerabilityStatus.OPEN
    )


def test_invalid_affected_range_returns_unknown() -> None:
    comparator = RubyVersionComparator()

    remediation = _remediation(
        RemediationRule(
            affected_range="~> invalid",
        ),
    )

    assert (
        comparator.determine_status("7.1.2", remediation)
        is VulnerabilityStatus.UNKNOWN
    )


def test_recommended_version_uses_matching_rule() -> None:
    comparator = RubyVersionComparator()

    result = comparator.recommended_version(
        "3.5.0",
        _remediation(
            RemediationRule(
                introduced="1.0.0",
                fixed="2.0.0",
            ),
            RemediationRule(
                introduced="3.0.0",
                fixed="4.0.0",
            ),
        ),
    )

    assert result == "4.0.0"


def test_recommended_version_uses_matching_affected_range() -> None:
    comparator = RubyVersionComparator()

    result = comparator.recommended_version(
        "3.5.0",
        _remediation(
            RemediationRule(
                affected_range=">=1.0.0 <2.0.0",
                fixed="2.0.0",
            ),
            RemediationRule(
                affected_range=">=3.0.0 <4.0.0",
                fixed="4.0.0",
            ),
        ),
    )

    assert result == "4.0.0"


def test_recommended_version_returns_none_for_open_ended_rule() -> None:
    comparator = RubyVersionComparator()

    result = comparator.recommended_version(
        "3.5.0",
        _remediation(
            RemediationRule(
                introduced="3.0.0",
            ),
        ),
    )

    assert result is None
