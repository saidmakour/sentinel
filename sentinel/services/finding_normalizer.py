from collections import defaultdict
from dataclasses import replace
from typing import TypeVar

from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.severity import Severity
from sentinel.log.logger import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


class FindingNormalizer:
    @staticmethod
    def _first_not_none(
        values: list[T | None],
    ) -> T | None:
        for value in values:
            if value is not None:
                return value

        return None

    def normalize(
        self,
        findings: list[VulnerabilityInfo],
    ) -> list[VulnerabilityInfo]:
        """
        Merge duplicate findings emitted by different providers.
        """
        groups = self._group(
            findings,
        )

        normalized = [self._merge(group) for group in groups.values()]

        return normalized

    def _group(
        self,
        findings: list[VulnerabilityInfo],
    ) -> dict[
        tuple[str, str, str],
        list[VulnerabilityInfo],
    ]:
        groups: defaultdict[
            tuple[str, str, str],
            list[VulnerabilityInfo],
        ] = defaultdict(list)

        for finding in findings:
            logger.debug(
                "NORMALIZE INPUT id=%s aliases=%s source=%s dep=%s",
                finding.identifier,
                finding.aliases,
                finding.sources,
                finding.dependency_name,
            )

            groups[self._group_key(finding)].append(
                finding,
            )

        return groups

    def _merge(
        self,
        findings: list[VulnerabilityInfo],
    ) -> VulnerabilityInfo:

        merged = replace(
            findings[0],
        )

        merged.identifier = self._canonical_identifier(
            findings[0],
        )

        self._merge_aliases(
            merged,
            findings,
        )

        self._merge_sources(
            merged,
            findings,
        )

        self._merge_ecosystem(
            merged,
            findings,
        )

        merged.severity = self._merge_severity(
            findings,
        )

        self._merge_cvss(
            merged,
            findings,
        )

        self._merge_known_exploited(
            merged,
            findings,
        )

        self._merge_kev(
            merged,
            findings,
        )

        self._merge_vulncheck_kev(
            merged,
            findings,
        )

        self._merge_epss(
            merged,
            findings,
        )

        self._merge_summary(
            merged,
            findings,
        )

        self._merge_remediation(
            merged,
            findings,
        )

        self._merge_fixed_versions(
            merged,
            findings,
        )
        logger.debug(
            "MERGING GROUP size=%s ids=%s sources=%s",
            len(findings),
            [finding.identifier for finding in findings],
            [finding.sources for finding in findings],
        )

        return merged

    def _canonical_identifier(
        self,
        finding: VulnerabilityInfo,
    ) -> str:

        identifiers = {
            finding.identifier,
            *finding.aliases,
        }

        cve = min(
            (
                identifier
                for identifier in identifiers
                if identifier.startswith("CVE-")
            ),
            default=None,
        )

        if cve is not None:
            return cve

        return min(
            identifiers,
        )

    def _merge_aliases(
        self,
        merged: VulnerabilityInfo,
        findings: list[VulnerabilityInfo],
    ) -> None:

        identifiers = {
            identifier
            for finding in findings
            for identifier in (
                finding.identifier,
                *finding.aliases,
            )
        }

        identifiers.discard(
            merged.identifier,
        )

        merged.aliases = sorted(
            identifiers,
        )

    def _merge_sources(
        self,
        merged: VulnerabilityInfo,
        findings: list[VulnerabilityInfo],
    ) -> None:

        merged.sources = list(
            dict.fromkeys(
                source for finding in findings for source in finding.sources
            )
        )

    def _merge_cvss(
        self,
        merged: VulnerabilityInfo,
        findings: list[VulnerabilityInfo],
    ) -> None:

        scores = [
            finding.cvss for finding in findings if finding.cvss is not None
        ]

        merged.cvss = max(scores) if scores else None

    def _merge_severity(
        self,
        findings: list[VulnerabilityInfo],
    ) -> Severity:

        return max(
            (finding.severity for finding in findings),
            key=lambda severity: severity.priority,
            default=Severity.UNKNOWN,
        )

    def _merge_known_exploited(
        self,
        merged: VulnerabilityInfo,
        findings: list[VulnerabilityInfo],
    ) -> None:

        merged.known_exploited = any(
            finding.known_exploited for finding in findings
        )

    def _merge_kev(
        self,
        merged: VulnerabilityInfo,
        findings: list[VulnerabilityInfo],
    ) -> None:

        merged.kev_date_added = self._first_not_none(
            [finding.kev_date_added for finding in findings]
        )

        merged.kev_vendor = self._first_not_none(
            [finding.kev_vendor for finding in findings]
        )

        merged.kev_product = self._first_not_none(
            [finding.kev_product for finding in findings]
        )

        merged.kev_required_action = self._first_not_none(
            [finding.kev_required_action for finding in findings]
        )

        merged.kev_known_ransomware = self._first_not_none(
            [finding.kev_known_ransomware for finding in findings]
        )

    def _merge_vulncheck_kev(
        self,
        merged: VulnerabilityInfo,
        findings: list[VulnerabilityInfo],
    ) -> None:

        merged.vulncheck_known_exploited = any(
            finding.vulncheck_known_exploited for finding in findings
        )

        merged.vulncheck_date_added = self._first_not_none(
            [finding.vulncheck_date_added for finding in findings]
        )

        merged.vulncheck_cisa_date_added = self._first_not_none(
            [finding.vulncheck_cisa_date_added for finding in findings]
        )

        merged.vulncheck_due_date = self._first_not_none(
            [finding.vulncheck_due_date for finding in findings]
        )

        merged.vulncheck_vendor = self._first_not_none(
            [finding.vulncheck_vendor for finding in findings]
        )

        merged.vulncheck_product = self._first_not_none(
            [finding.vulncheck_product for finding in findings]
        )

        merged.vulncheck_required_action = self._first_not_none(
            [finding.vulncheck_required_action for finding in findings]
        )

        merged.vulncheck_known_ransomware = self._first_not_none(
            [finding.vulncheck_known_ransomware for finding in findings]
        )

        merged.vulncheck_reported_exploited_by_canaries = any(
            finding.vulncheck_reported_exploited_by_canaries
            for finding in findings
        )

    def _merge_epss(
        self,
        merged: VulnerabilityInfo,
        findings: list[VulnerabilityInfo],
    ) -> None:

        scores = [
            finding.epss_score
            for finding in findings
            if finding.epss_score is not None
        ]

        percentiles = [
            finding.epss_percentile
            for finding in findings
            if finding.epss_percentile is not None
        ]

        merged.epss_score = max(scores) if scores else None
        merged.epss_percentile = max(percentiles) if percentiles else None

    def _merge_summary(
        self,
        merged: VulnerabilityInfo,
        findings: list[VulnerabilityInfo],
    ) -> None:

        summaries = [
            finding.summary for finding in findings if finding.summary
        ]

        merged.summary = (
            max(
                summaries,
                key=len,
            )
            if summaries
            else ""
        )

    def _merge_remediation(
        self,
        merged: VulnerabilityInfo,
        findings: list[VulnerabilityInfo],
    ) -> None:

        rules: list[RemediationRule] = []

        for finding in findings:
            if finding.remediation is None:
                continue

            rules.extend(
                finding.remediation.rules,
            )

        if not rules:
            merged.remediation = None
            return

        merged.remediation = RemediationInfo(
            rules=self._deduplicate_remediation_rules(
                rules,
            ),
        )

        logger.info(
            "MERGE REMEDIATION: id=%s sources=%s rules=%s",
            merged.identifier,
            merged.sources,
            [
                (
                    rule.introduced,
                    rule.fixed,
                    rule.affected_range,
                )
                for finding in findings
                if finding.remediation is not None
                for rule in finding.remediation.rules
            ],
        )

    def _deduplicate_remediation_rules(
        self,
        rules: list[RemediationRule],
    ) -> list[RemediationRule]:

        unique: dict[
            tuple[str | None, str | None, str | None],
            RemediationRule,
        ] = {}

        for rule in rules:
            key = (
                rule.introduced,
                rule.fixed,
                rule.affected_range,
            )

            unique[key] = rule

        return list(
            unique.values(),
        )

    def _merge_ecosystem(
        self,
        merged: VulnerabilityInfo,
        findings: list[VulnerabilityInfo],
    ) -> None:

        ecosystems: set[Ecosystem] = {
            finding.ecosystem for finding in findings
        }

        if len(ecosystems) > 1:
            logger.debug(
                "Multiple ecosystems found for dependency=%s: %s",
                merged.dependency_name,
                ecosystems,
            )

        merged.ecosystem = next(
            iter(ecosystems),
            merged.ecosystem,
        )

    def _merge_fixed_versions(
        self,
        merged: VulnerabilityInfo,
        findings: list[VulnerabilityInfo],
    ) -> None:
        versions = {
            version
            for finding in findings
            for version in finding.fixed_versions
        }

        merged.fixed_versions = sorted(
            versions,
        )

    def _group_key(
        self,
        finding: VulnerabilityInfo,
    ) -> tuple[str, str, str]:

        identifiers = [
            finding.identifier,
            *finding.aliases,
        ]

        cve_ids = [
            identifier
            for identifier in identifiers
            if identifier.startswith("CVE-")
        ]

        canonical = min(cve_ids) if cve_ids else min(identifiers)

        return (
            finding.dependency_name.lower(),
            finding.dependency_version,
            canonical,
        )
