from dataclasses import dataclass


@dataclass(slots=True)
class FindingStatistics:
    dependency_count: int
    occurrence_count: int
    unique_vulnerability_count: int
    unique_identifier_count: int
    provider_count: dict[str, int]
    dependency_occurrence_count: dict[str, int]
    duplicated_identifier_count: int
