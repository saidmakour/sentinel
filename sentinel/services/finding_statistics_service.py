from collections import Counter
from collections import Counter as CounterType

from sentinel.dto.finding_statistics import FindingStatistics
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo


class FindingStatisticsService:
    def build(
        self,
        dependencies: list[ScannedDependency],
        findings: list[VulnerabilityInfo],
    ) -> FindingStatistics:

        identifier_counter = Counter(
            finding.identifier for finding in findings
        )

        dependency_counter = Counter(
            finding.dependency_name for finding in findings
        )

        provider_counter: CounterType[str] = Counter()

        for finding in findings:
            provider_counter.update(
                provider.value for provider in finding.sources
            )

        duplicated = sum(
            1 for count in identifier_counter.values() if count > 1
        )

        return FindingStatistics(
            dependency_count=len(dependencies),
            occurrence_count=len(findings),
            unique_vulnerability_count=len(
                identifier_counter,
            ),
            unique_identifier_count=len(
                identifier_counter,
            ),
            provider_count=dict(
                provider_counter,
            ),
            dependency_occurrence_count=dict(
                dependency_counter,
            ),
            duplicated_identifier_count=duplicated,
        )
