from packaging.specifiers import InvalidSpecifier
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion
from packaging.version import Version

from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.services.version_comparators.base import BaseVersionComparator


class PyPIVersionComparator(BaseVersionComparator):
    def determine_status(
        self,
        installed_version: str,
        remediation: RemediationInfo,
    ) -> VulnerabilityStatus:

        if not remediation.rules:
            return VulnerabilityStatus.UNKNOWN

        try:
            installed = Version(
                installed_version,
            )
        except InvalidVersion:
            return VulnerabilityStatus.UNKNOWN

        valid_rules = self._parse_rules(
            remediation.rules,
        )

        if not valid_rules:
            return VulnerabilityStatus.UNKNOWN

        for introduced, fixed, affected_range in valid_rules:
            if affected_range is not None:
                if installed in affected_range:
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

        installed = self._parse_version(installed_version)
        if installed is None:
            return None

        valid_rules = self._parse_rules(remediation.rules)

        for introduced, fixed, affected_range in valid_rules:
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

            return str(fixed)

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
            Version | None,
            Version | None,
            SpecifierSet | None,
        ]
    ]:

        valid_rules: list[
            tuple[
                Version | None,
                Version | None,
                SpecifierSet | None,
            ]
        ] = []

        for rule in rules:
            introduced = self._parse_version(
                rule.introduced,
            )

            fixed = self._parse_version(
                rule.fixed,
            )

            affected_range = self._parse_specifier(
                rule.affected_range,
            )

            if rule.introduced is not None and introduced is None:
                continue

            if rule.fixed is not None and fixed is None:
                continue

            if rule.affected_range is not None and affected_range is None:
                continue

            valid_rules.append(
                (
                    introduced,
                    fixed,
                    affected_range,
                )
            )

        return valid_rules

    @staticmethod
    def _parse_version(
        value: str | None,
    ) -> Version | None:

        if value is None:
            return None

        try:
            return Version(
                value,
            )
        except InvalidVersion:
            return None

    @staticmethod
    def _parse_specifier(
        value: str | None,
    ) -> SpecifierSet | None:

        if value is None:
            return None

        try:
            return SpecifierSet(
                value,
            )
        except InvalidSpecifier:
            return None

    @staticmethod
    def _rule_applies(
        installed: Version,
        introduced: Version | None,
        fixed: Version | None,
        affected_range: SpecifierSet | None,
    ) -> bool:
        if affected_range is not None:
            return installed in affected_range

        if introduced is not None and installed < introduced:
            return False

        if fixed is not None and installed >= fixed:
            return False

        return True
