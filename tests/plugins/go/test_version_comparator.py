from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.plugins.go.version_comparator import GoVersionComparator


def remediation(
    *rules: RemediationRule,
) -> RemediationInfo:
    return RemediationInfo(rules=list(rules))


class TestGoVersionComparator:
    def test_compare_versions(self) -> None:
        comparator = GoVersionComparator()

        assert (
            comparator.compare_versions(
                "v1.2.3",
                "v1.2.4",
            )
            == -1
        )

        assert (
            comparator.compare_versions(
                "v1.2.4",
                "v1.2.3",
            )
            == 1
        )

        assert (
            comparator.compare_versions(
                "v1.2.3",
                "1.2.3",
            )
            == 0
        )

    def test_compare_versions_with_incompatible_suffix(self) -> None:
        comparator = GoVersionComparator()

        assert (
            comparator.compare_versions(
                "v2.0.0+incompatible",
                "v2.0.0",
            )
            == 0
        )

    def test_determine_status_open(self) -> None:
        comparator = GoVersionComparator()

        result = comparator.determine_status(
            "v1.5.0",
            remediation(
                RemediationRule(
                    introduced="v1.0.0",
                    fixed="v1.6.0",
                ),
            ),
        )

        assert result == VulnerabilityStatus.OPEN

    def test_determine_status_resolved(self) -> None:
        comparator = GoVersionComparator()

        result = comparator.determine_status(
            "v1.6.0",
            remediation(
                RemediationRule(
                    introduced="v1.0.0",
                    fixed="v1.6.0",
                ),
            ),
        )

        assert result == VulnerabilityStatus.RESOLVED

    def test_determine_status_before_introduction(self) -> None:
        comparator = GoVersionComparator()

        result = comparator.determine_status(
            "v0.9.0",
            remediation(
                RemediationRule(
                    introduced="v1.0.0",
                    fixed="v1.6.0",
                ),
            ),
        )

        assert result == VulnerabilityStatus.RESOLVED

    def test_determine_status_unknown_without_rules(self) -> None:
        comparator = GoVersionComparator()

        result = comparator.determine_status(
            "v1.5.0",
            RemediationInfo(rules=[]),
        )

        assert result == VulnerabilityStatus.UNKNOWN

    def test_determine_status_unknown_for_invalid_version(
        self,
    ) -> None:
        comparator = GoVersionComparator()

        result = comparator.determine_status(
            "invalid",
            remediation(
                RemediationRule(
                    introduced="v1.0.0",
                    fixed="v1.6.0",
                ),
            ),
        )

        assert result == VulnerabilityStatus.UNKNOWN

    def test_determine_status_with_affected_range(self) -> None:
        comparator = GoVersionComparator()

        result = comparator.determine_status(
            "v1.5.0",
            remediation(
                RemediationRule(
                    affected_range=">=v1.0.0 <v2.0.0",
                ),
            ),
        )

        assert result == VulnerabilityStatus.OPEN

    def test_affected_range_outside_range(self) -> None:
        comparator = GoVersionComparator()

        result = comparator.determine_status(
            "v2.0.0",
            remediation(
                RemediationRule(
                    affected_range=">=v1.0.0 <v2.0.0",
                ),
            ),
        )

        assert result == VulnerabilityStatus.RESOLVED

    def test_recommended_version(self) -> None:
        comparator = GoVersionComparator()

        result = comparator.recommended_version(
            "v1.5.0",
            remediation(
                RemediationRule(
                    fixed="v1.6.0",
                ),
                RemediationRule(
                    fixed="v1.7.0",
                ),
            ),
        )

        assert result == "v1.6.0"

    def test_recommended_version_ignores_older_versions(
        self,
    ) -> None:
        comparator = GoVersionComparator()

        result = comparator.recommended_version(
            "v1.6.0",
            remediation(
                RemediationRule(
                    fixed="v1.5.0",
                ),
                RemediationRule(
                    fixed="v1.7.0",
                ),
            ),
        )

        assert result == "v1.7.0"

    def test_recommended_version_returns_none_when_unavailable(
        self,
    ) -> None:
        comparator = GoVersionComparator()

        result = comparator.recommended_version(
            "v1.6.0",
            remediation(
                RemediationRule(
                    fixed="v1.5.0",
                ),
            ),
        )

        assert result is None


def test_recommended_version_uses_matching_rule() -> None:
    comparator = GoVersionComparator()

    result = comparator.recommended_version(
        "v3.5.0",
        remediation(
            RemediationRule(
                introduced="v1.0.0",
                fixed="v2.0.0",
            ),
            RemediationRule(
                introduced="v3.0.0",
                fixed="v4.0.0",
            ),
        ),
    )

    assert result == "v4.0.0"


def test_recommended_version_uses_matching_affected_range() -> None:
    comparator = GoVersionComparator()

    result = comparator.recommended_version(
        "v3.5.0",
        remediation(
            RemediationRule(
                affected_range=">=v1.0.0 <v2.0.0",
                fixed="v2.0.0",
            ),
            RemediationRule(
                affected_range=">=v3.0.0 <v4.0.0",
                fixed="v4.0.0",
            ),
        ),
    )

    assert result == "v4.0.0"


def test_recommended_version_returns_none_for_open_ended_rule() -> None:
    comparator = GoVersionComparator()

    result = comparator.recommended_version(
        "v3.5.0",
        remediation(
            RemediationRule(
                introduced="v3.0.0",
            ),
        ),
    )

    assert result is None
