from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.plugins.python.version_comparator import PyPIVersionComparator


def test_pypi_comparator_can_be_created() -> None:
    comparator = PyPIVersionComparator()

    assert comparator is not None


def test_unknown_when_no_remediation_rules() -> None:
    comparator = PyPIVersionComparator()

    result = comparator.determine_status(
        installed_version="1.0.0",
        remediation=RemediationInfo(),
    )

    assert result == VulnerabilityStatus.UNKNOWN


def test_unknown_when_installed_version_is_invalid() -> None:
    comparator = PyPIVersionComparator()

    result = comparator.determine_status(
        installed_version="invalid-version",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="1.0.0",
                    fixed="2.0.0",
                ),
            ],
        ),
    )

    assert result == VulnerabilityStatus.UNKNOWN


def test_unknown_when_all_rule_versions_are_invalid() -> None:
    comparator = PyPIVersionComparator()

    result = comparator.determine_status(
        installed_version="1.0.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="invalid",
                    fixed="also-invalid",
                ),
            ],
        ),
    )

    assert result == VulnerabilityStatus.UNKNOWN


def test_open_when_installed_version_is_inside_vulnerable_range() -> None:
    comparator = PyPIVersionComparator()

    result = comparator.determine_status(
        installed_version="1.5.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="1.0.0",
                    fixed="2.0.0",
                ),
            ],
        ),
    )

    assert result == VulnerabilityStatus.OPEN


def test_resolved_when_installed_version_equals_fixed_version() -> None:
    comparator = PyPIVersionComparator()

    result = comparator.determine_status(
        installed_version="2.0.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="1.0.0",
                    fixed="2.0.0",
                ),
            ],
        ),
    )

    assert result == VulnerabilityStatus.RESOLVED


def test_resolved_when_installed_version_is_higher_than_fixed() -> None:
    comparator = PyPIVersionComparator()

    result = comparator.determine_status(
        installed_version="3.0.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="1.0.0",
                    fixed="2.0.0",
                ),
            ],
        ),
    )

    assert result == VulnerabilityStatus.RESOLVED


def test_resolved_when_installed_version_is_before_introduced() -> None:
    comparator = PyPIVersionComparator()

    result = comparator.determine_status(
        installed_version="0.9.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="1.0.0",
                    fixed="2.0.0",
                ),
            ],
        ),
    )

    assert result == VulnerabilityStatus.RESOLVED


def test_open_when_installed_version_is_inside_second_vulnerable_range() -> (
    None
):
    comparator = PyPIVersionComparator()

    result = comparator.determine_status(
        installed_version="2.1.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="1.0.0",
                    fixed="1.5.0",
                ),
                RemediationRule(
                    introduced="2.0.0",
                    fixed="2.3.0",
                ),
            ],
        ),
    )

    assert result == VulnerabilityStatus.OPEN


def test_resolved_when_installed_version_is_between_two_vulnerable_ranges() -> (
    None
):
    comparator = PyPIVersionComparator()

    result = comparator.determine_status(
        installed_version="1.8.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="1.0.0",
                    fixed="1.5.0",
                ),
                RemediationRule(
                    introduced="2.0.0",
                    fixed="2.3.0",
                ),
            ],
        ),
    )

    assert result == VulnerabilityStatus.RESOLVED


def test_open_when_no_introduced_version_and_before_fixed() -> None:
    comparator = PyPIVersionComparator()

    result = comparator.determine_status(
        installed_version="1.5.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    fixed="2.0.0",
                ),
            ],
        ),
    )

    assert result == VulnerabilityStatus.OPEN


def test_resolved_when_no_introduced_version_and_at_fixed() -> None:
    comparator = PyPIVersionComparator()

    result = comparator.determine_status(
        installed_version="2.0.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    fixed="2.0.0",
                ),
            ],
        ),
    )

    assert result == VulnerabilityStatus.RESOLVED


def test_open_when_no_fixed_version() -> None:
    comparator = PyPIVersionComparator()

    result = comparator.determine_status(
        installed_version="2.0.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="1.0.0",
                ),
            ],
        ),
    )

    assert result == VulnerabilityStatus.OPEN


def test_open_when_installed_version_is_inside_affected_range() -> None:
    comparator = PyPIVersionComparator()

    result = comparator.determine_status(
        installed_version="1.5.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    affected_range=">=1.0.0,<2.0.0",
                ),
            ],
        ),
    )

    assert result == VulnerabilityStatus.OPEN


def test_resolved_when_installed_version_is_outside_affected_range() -> None:
    comparator = PyPIVersionComparator()

    result = comparator.determine_status(
        installed_version="2.0.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    affected_range=">=1.0.0,<2.0.0",
                ),
            ],
        ),
    )

    assert result == VulnerabilityStatus.RESOLVED


def test_recommended_version_returns_fixed_version() -> None:
    comparator = PyPIVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="2.0.0",
                fixed="2.32.0",
                affected_range="<2.32.0",
            ),
        ],
    )

    result = comparator.recommended_version(
        installed_version="2.31.0",
        remediation=remediation,
    )

    assert result == "2.32.0"


def test_recommended_version_returns_none_when_already_fixed() -> None:
    comparator = PyPIVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="2.0.0",
                fixed="2.32.0",
                affected_range="<2.32.0",
            ),
        ],
    )

    result = comparator.recommended_version(
        installed_version="2.32.0",
        remediation=remediation,
    )

    assert result is None


def test_recommended_version_returns_lowest_fixed_version_above_installed() -> (
    None
):
    comparator = PyPIVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="2.0.0",
                fixed="2.32.0",
                affected_range="<2.32.0",
            ),
            RemediationRule(
                introduced="2.0.0",
                fixed="2.33.0",
                affected_range="<2.33.0",
            ),
        ],
    )

    result = comparator.recommended_version(
        installed_version="2.31.0",
        remediation=remediation,
    )

    assert result == "2.32.0"


def test_recommended_version_returns_none_without_rules() -> None:
    comparator = PyPIVersionComparator()

    remediation = RemediationInfo(
        rules=[],
    )

    result = comparator.recommended_version(
        installed_version="2.31.0",
        remediation=remediation,
    )

    assert result is None


def test_recommended_version_returns_none_for_invalid_installed_version() -> (
    None
):
    comparator = PyPIVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="2.0.0",
                fixed="2.32.0",
                affected_range="<2.32.0",
            ),
        ],
    )

    result = comparator.recommended_version(
        installed_version="not-a-version",
        remediation=remediation,
    )

    assert result is None


def test_compare_versions_returns_negative_when_first_is_lower() -> None:
    comparator = PyPIVersionComparator()

    assert (
        comparator.compare_versions(
            "2.31.0",
            "2.32.0",
        )
        < 0
    )


def test_compare_versions_returns_positive_when_first_is_higher() -> None:
    comparator = PyPIVersionComparator()

    assert (
        comparator.compare_versions(
            "2.33.0",
            "2.32.0",
        )
        > 0
    )


def test_compare_versions_returns_zero_when_versions_are_equal() -> None:
    comparator = PyPIVersionComparator()

    assert (
        comparator.compare_versions(
            "2.32.0",
            "2.32.0",
        )
        == 0
    )


def test_compare_versions_uses_semantic_versioning() -> None:
    comparator = PyPIVersionComparator()

    assert (
        comparator.compare_versions(
            "2.10.0",
            "2.9.0",
        )
        > 0
    )


def test_recommended_version_uses_matching_rule() -> None:
    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                affected_range=">=1.0,<2.0",
                fixed="2.0",
            ),
            RemediationRule(
                affected_range=">=3.0,<4.0",
                fixed="4.0",
            ),
        ],
    )

    comparator = PyPIVersionComparator()

    assert (
        comparator.recommended_version(
            "3.5",
            remediation,
        )
        == "4.0"
    )


def test_recommended_version_returns_none_when_no_rule_applies() -> None:
    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                affected_range=">=1.0,<2.0",
                fixed="2.0",
            ),
            RemediationRule(
                affected_range=">=3.0,<4.0",
                fixed="4.0",
            ),
        ],
    )

    comparator = PyPIVersionComparator()

    assert (
        comparator.recommended_version(
            "2.5",
            remediation,
        )
        is None
    )


def test_recommended_version_returns_none_for_open_ended_rule() -> None:
    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="2.0",
            ),
        ],
    )

    comparator = PyPIVersionComparator()

    assert (
        comparator.recommended_version(
            "3.0",
            remediation,
        )
        is None
    )
