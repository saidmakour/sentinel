import re

from packaging.version import InvalidVersion
from packaging.version import Version

from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.services.version_comparators.base import BaseVersionComparator


class PHPVersionComparator(BaseVersionComparator):
    def determine_status(
        self,
        installed_version: str,
        remediation: RemediationInfo,
    ) -> VulnerabilityStatus:

        if not remediation.rules:
            return VulnerabilityStatus.UNKNOWN

        installed = self._parse_version(
            installed_version,
        )

        if installed is None:
            return VulnerabilityStatus.UNKNOWN

        valid_rules = [
            rule for rule in remediation.rules if self._is_valid_rule(rule)
        ]

        if not valid_rules:
            return VulnerabilityStatus.UNKNOWN

        for rule in valid_rules:
            if rule.affected_range is not None:
                affected = self._is_in_affected_range(
                    installed,
                    rule.affected_range,
                )

                if affected:
                    return VulnerabilityStatus.OPEN

                continue

            introduced = self._parse_version(
                rule.introduced,
            )

            fixed = self._parse_version(
                rule.fixed,
            )

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

        valid_rules = [
            rule for rule in remediation.rules if self._is_valid_rule(rule)
        ]

        for rule in valid_rules:
            fixed = self._parse_version(
                rule.fixed,
            )

            if not self._rule_applies(
                installed,
                rule,
            ):
                continue

            if fixed is None:
                return None

            if fixed <= installed:
                return None

            return str(fixed)

        return None

    def compare_versions(
        self,
        version_a: str,
        version_b: str,
    ) -> int:
        first = self._parse_version(
            version_a,
        )

        second = self._parse_version(
            version_b,
        )

        if first is None or second is None:
            return 0

        if first < second:
            return -1

        if first > second:
            return 1

        return 0

    @classmethod
    def _is_valid_rule(
        cls,
        rule: RemediationRule,
    ) -> bool:

        if rule.introduced is not None:
            if cls._parse_version(rule.introduced) is None:
                return False

        if rule.fixed is not None:
            if cls._parse_version(rule.fixed) is None:
                return False

        if rule.affected_range is not None:
            if not cls._is_valid_constraint(
                rule.affected_range,
            ):
                return False

        return True

    @staticmethod
    def _parse_version(
        value: str | None,
    ) -> Version | None:

        if value is None:
            return None

        # PHP versions commonly contain a leading "v".
        normalized = value.strip()

        if normalized.lower().startswith("v"):
            normalized = normalized[1:]

        try:
            return Version(normalized)
        except InvalidVersion:
            return None

    @classmethod
    def _is_in_affected_range(
        cls,
        installed: Version,
        constraint: str,
    ) -> bool:

        constraints = cls._split_constraints(
            constraint,
        )

        if not constraints:
            return False

        return all(
            cls._matches_constraint(
                installed,
                item,
            )
            for item in constraints
        )

    @staticmethod
    def _split_constraints(
        constraint: str,
    ) -> list[str]:

        normalized = constraint.replace(
            ",",
            " ",
        )

        return [item for item in normalized.split() if item]

    @classmethod
    def _matches_constraint(
        cls,
        installed: Version,
        constraint: str,
    ) -> bool:

        constraint = constraint.strip()

        if constraint.startswith("^"):
            return cls._matches_caret(
                installed,
                constraint[1:],
            )

        if constraint.startswith("~"):
            return cls._matches_tilde(
                installed,
                constraint[1:],
            )

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

        version = cls._parse_version(
            constraint,
        )

        if version is None:
            return False

        return installed == version

    @staticmethod
    def _compare(
        installed: Version,
        operator: str,
        version: Version,
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
    def _matches_caret(
        cls,
        installed: Version,
        value: str,
    ) -> bool:

        version = cls._parse_version(value)

        if version is None:
            return False

        upper = cls._caret_upper_bound(
            version,
        )

        return installed >= version and installed < upper

    @staticmethod
    def _caret_upper_bound(
        version: Version,
    ) -> Version:

        release = list(version.release)

        if not release:
            return version

        if release[0] > 0:
            return Version(
                f"{release[0] + 1}.0.0",
            )

        if len(release) > 1 and release[1] > 0:
            return Version(
                f"0.{release[1] + 1}.0",
            )

        patch = release[2] if len(release) > 2 else 0

        return Version(
            f"0.0.{patch + 1}",
        )

    @classmethod
    def _matches_tilde(
        cls,
        installed: Version,
        value: str,
    ) -> bool:

        version = cls._parse_version(value)

        if version is None:
            return False

        release = list(version.release)

        if len(release) <= 1:
            upper = Version(
                f"{release[0] + 1}.0.0",
            )
        else:
            upper = Version(
                f"{release[0]}.{release[1] + 1}.0",
            )

        return installed >= version and installed < upper

    @staticmethod
    def _is_valid_constraint(
        constraint: str,
    ) -> bool:
        if not constraint.strip():
            return False

        pattern = re.compile(
            r"^(?:"
            r"\^|~|>=|<=|>|<|="
            r")?"
            r"v?\d+(?:\.\d+)*"
            r"(?:[-+][0-9A-Za-z.-]+)?$",
        )

        parts = constraint.replace(
            ",",
            " ",
        ).split()

        return bool(parts) and all(
            pattern.match(part) is not None for part in parts
        )

    @classmethod
    def _rule_applies(
        cls,
        installed: Version,
        rule: RemediationRule,
    ) -> bool:
        if rule.affected_range is not None:
            return cls._is_in_affected_range(
                installed,
                rule.affected_range,
            )

        introduced = cls._parse_version(
            rule.introduced,
        )
        fixed = cls._parse_version(
            rule.fixed,
        )

        if introduced is not None and installed < introduced:
            return False

        if fixed is not None and installed >= fixed:
            return False

        return True
