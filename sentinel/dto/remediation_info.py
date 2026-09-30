from dataclasses import dataclass
from dataclasses import field
from typing import TypedDict


class RemediationRuleData(TypedDict):
    introduced: str | None
    fixed: str | None
    affected_range: str | None


class RemediationData(TypedDict):
    rules: list[RemediationRuleData]


@dataclass(slots=True)
class RemediationRule:
    introduced: str | None = None
    fixed: str | None = None
    affected_range: str | None = None


@dataclass(slots=True)
class RemediationInfo:
    rules: list[RemediationRule] = field(
        default_factory=list[RemediationRule],
    )
