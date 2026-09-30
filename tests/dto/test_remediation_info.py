from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule


def test_remediation_info_can_be_created() -> None:
    remediation = RemediationInfo()

    assert remediation is not None


def test_remediation_info_values() -> None:
    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced=None,
                fixed="2.32.3",
                affected_range="<2.32.3",
            ),
        ],
    )

    assert remediation.rules[0].affected_range == "<2.32.3"
    assert remediation.rules[0].fixed == "2.32.3"
