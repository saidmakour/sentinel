from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.plugins.node.version_comparator import NPMVersionComparator


def test_version_before_fixed_version_is_open() -> None:
    comparator = NPMVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                fixed="2.0.0",
            ),
        ],
    )

    status = comparator.determine_status(
        installed_version="1.5.0",
        remediation=remediation,
    )

    assert status == VulnerabilityStatus.OPEN


def test_version_at_fixed_version_is_resolved() -> None:
    comparator = NPMVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                fixed="2.0.0",
            ),
        ],
    )

    status = comparator.determine_status(
        installed_version="2.0.0",
        remediation=remediation,
    )

    assert status == VulnerabilityStatus.RESOLVED


def test_version_after_fixed_version_is_resolved() -> None:
    comparator = NPMVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                fixed="2.0.0",
            ),
        ],
    )

    status = comparator.determine_status(
        installed_version="2.5.0",
        remediation=remediation,
    )

    assert status == VulnerabilityStatus.RESOLVED


def test_affected_range() -> None:
    comparator = NPMVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                affected_range=">=1.0.0 <2.0.0",
            ),
        ],
    )

    status = comparator.determine_status(
        installed_version="1.5.0",
        remediation=remediation,
    )

    assert status == VulnerabilityStatus.OPEN


def test_affected_range_outside_range() -> None:
    comparator = NPMVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                affected_range=">=1.0.0 <2.0.0",
            ),
        ],
    )

    status = comparator.determine_status(
        installed_version="2.0.0",
        remediation=remediation,
    )

    assert status == VulnerabilityStatus.RESOLVED


def test_invalid_installed_version() -> None:
    comparator = NPMVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                fixed="2.0.0",
            ),
        ],
    )

    status = comparator.determine_status(
        installed_version="not-a-version",
        remediation=remediation,
    )

    assert status == VulnerabilityStatus.UNKNOWN


def test_empty_remediation() -> None:
    comparator = NPMVersionComparator()

    status = comparator.determine_status(
        installed_version="1.0.0",
        remediation=RemediationInfo(),
    )

    assert status == VulnerabilityStatus.UNKNOWN


def test_compare_versions() -> None:
    comparator = NPMVersionComparator()

    assert (
        comparator.compare_versions(
            "1.2.3",
            "1.10.0",
        )
        < 0
    )

    assert (
        comparator.compare_versions(
            "1.10.0",
            "1.2.3",
        )
        > 0
    )

    assert (
        comparator.compare_versions(
            "1.2.3",
            "1.2.3",
        )
        == 0
    )


def test_compare_versions_handles_prerelease() -> None:
    comparator = NPMVersionComparator()

    assert (
        comparator.compare_versions(
            "1.2.3-beta.1",
            "1.2.3",
        )
        < 0
    )


def test_recommended_version_returns_fixed_version() -> None:
    comparator = NPMVersionComparator()

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
    comparator = NPMVersionComparator()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="1.0.0",
                fixed="1.2.3",
                affected_range="<1.2.3",
            ),
            RemediationRule(
                introduced="1.2.0",
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


def test_recommended_version_uses_matching_rule() -> None:
    comparator = NPMVersionComparator()

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
    comparator = NPMVersionComparator()

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
    comparator = NPMVersionComparator()

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
