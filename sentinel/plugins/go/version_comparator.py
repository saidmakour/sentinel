from __future__ import annotations

from dataclasses import dataclass

from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.services.version_comparators.base import BaseVersionComparator


@dataclass(frozen=True)
class _GoVersion:
    components: tuple[int, ...]

    def __lt__(
        self,
        other: _GoVersion,
    ) -> bool:
        return self.components < other.components

    def __le__(
        self,
        other: _GoVersion,
    ) -> bool:
        return self.components <= other.components

    def __ge__(
        self,
        other: _GoVersion,
    ) -> bool:
        return self.components >= other.components

    def __gt__(
        self,
        other: _GoVersion,
    ) -> bool:
        return self.components > other.components

    def __eq__(
        self,
        other: object,
    ) -> bool:
        if not isinstance(other, _GoVersion):
            return NotImplemented

        return self.components == other.components


class GoVersionComparator(BaseVersionComparator):
    def determine_status(
        self,
        installed_version: str,
        remediation: RemediationInfo,
    ) -> VulnerabilityStatus:
        if not remediation.rules:
            return VulnerabilityStatus.UNKNOWN

        installed = self._parse_version(installed_version)

        if installed is None:
            return VulnerabilityStatus.UNKNOWN

        valid_rules = self._parse_rules(remediation.rules)

        if not valid_rules:
            return VulnerabilityStatus.UNKNOWN

        for introduced, fixed, affected_range in valid_rules:
            if affected_range is not None:
                if self._matches_range(
                    installed,
                    affected_range,
                ):
                    return VulnerabilityStatus.OPEN

                continue

            if introduced is not None and installed < introduced:
                continue

            if fixed is not None and installed >= fixed:
                continue

            return VulnerabilityStatus.OPEN

        return VulnerabilityStatus.RESOLVED

    def recommended_version(
        self,
        installed_version: str,
        remediation: RemediationInfo,
    ) -> str | None:
        if not remediation.rules:
            return None

        installed = self._parse_version(
            installed_version,
        )

        if installed is None:
            return None

        valid_rules = self._parse_rules(
            remediation.rules,
        )

        for (
            introduced,
            fixed,
            affected_range,
        ) in valid_rules:
            if not self._rule_applies(
                installed,
                introduced,
                fixed,
                affected_range,
            ):
                continue

            if fixed is None:
                return None

            if fixed <= installed:
                return None

            return self._format_version(
                fixed,
            )

        return None

    def compare_versions(
        self,
        version_a: str,
        version_b: str,
    ) -> int:
        first = self._parse_version(version_a)
        second = self._parse_version(version_b)

        if first is None or second is None:
            return 0

        if first < second:
            return -1

        if first > second:
            return 1

        return 0

    def _parse_rules(
        self,
        rules: list[RemediationRule],
    ) -> list[
        tuple[
            _GoVersion | None,
            _GoVersion | None,
            str | None,
        ]
    ]:
        valid_rules: list[
            tuple[
                _GoVersion | None,
                _GoVersion | None,
                str | None,
            ]
        ] = []

        for rule in rules:
            introduced = self._parse_version(rule.introduced)
            fixed = self._parse_version(rule.fixed)

            if rule.introduced is not None and introduced is None:
                continue

            if rule.fixed is not None and fixed is None:
                continue

            if rule.affected_range is not None and not self._is_valid_range(
                rule.affected_range,
            ):
                continue

            valid_rules.append(
                (
                    introduced,
                    fixed,
                    rule.affected_range,
                )
            )

        return valid_rules

    @staticmethod
    def _parse_version(
        value: str | None,
    ) -> _GoVersion | None:
        if value is None:
            return None

        normalized = value.strip()

        if not normalized:
            return None

        if normalized.startswith("v"):
            normalized = normalized[1:]

        # Go module versions may use +incompatible.
        normalized = normalized.split(
            "+",
            maxsplit=1,
        )[0]

        # Ignore pre-release suffixes for the initial comparator.
        normalized = normalized.split(
            "-",
            maxsplit=1,
        )[0]

        parts = normalized.split(".")

        if not parts or any(not part.isdigit() for part in parts):
            return None

        return _GoVersion(
            components=tuple(int(part) for part in parts),
        )

    @classmethod
    def _matches_range(
        cls,
        installed: _GoVersion,
        affected_range: str,
    ) -> bool:
        constraints = cls._split_constraints(
            affected_range,
        )

        if not constraints:
            return False

        return all(
            cls._matches_constraint(
                installed,
                constraint,
            )
            for constraint in constraints
        )

    @staticmethod
    def _split_constraints(
        affected_range: str,
    ) -> list[str]:
        return [
            item
            for item in affected_range.replace(
                ",",
                " ",
            ).split()
            if item
        ]

    @classmethod
    def _matches_constraint(
        cls,
        installed: _GoVersion,
        constraint: str,
    ) -> bool:
        operators = (
            ">=",
            "<=",
            ">",
            "<",
            "=",
        )

        for operator in operators:
            if constraint.startswith(operator):
                version = cls._parse_version(
                    constraint[len(operator) :],
                )

                if version is None:
                    return False

                return cls._compare(
                    installed,
                    operator,
                    version,
                )

        version = cls._parse_version(constraint)

        if version is None:
            return False

        return installed == version

    @staticmethod
    def _compare(
        installed: _GoVersion,
        operator: str,
        version: _GoVersion,
    ) -> bool:
        if operator == ">=":
            return installed >= version

        if operator == "<=":
            return installed <= version

        if operator == ">":
            return installed > version

        if operator == "<":
            return installed < version

        return installed == version

    @classmethod
    def _is_valid_range(
        cls,
        affected_range: str,
    ) -> bool:
        constraints = cls._split_constraints(
            affected_range,
        )

        if not constraints:
            return False

        return all(
            cls._is_valid_constraint(
                constraint,
            )
            for constraint in constraints
        )

    @classmethod
    def _is_valid_constraint(
        cls,
        constraint: str,
    ) -> bool:
        operators = (
            ">=",
            "<=",
            ">",
            "<",
            "=",
        )

        value = constraint

        for operator in operators:
            if constraint.startswith(operator):
                value = constraint[len(operator) :]
                break

        return cls._parse_version(value) is not None

    @classmethod
    def _rule_applies(
        cls,
        installed: _GoVersion,
        introduced: _GoVersion | None,
        fixed: _GoVersion | None,
        affected_range: str | None,
    ) -> bool:
        if affected_range is not None:
            return cls._matches_range(
                installed,
                affected_range,
            )

        if introduced is not None and installed < introduced:
            return False

        if fixed is not None and installed >= fixed:
            return False

        return True

    @staticmethod
    def _format_version(
        version: _GoVersion,
    ) -> str:
        return "v" + ".".join(
            str(component) for component in version.components
        )
