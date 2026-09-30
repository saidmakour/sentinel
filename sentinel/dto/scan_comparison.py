from __future__ import annotations

from dataclasses import dataclass

from sentinel.models.finding import Finding


@dataclass(slots=True)
class ScanComparison:
    """
    Represents the differences between two scans.
    """

    previous_scan_id: int
    current_scan_id: int

    added: list[Finding]
    resolved: list[Finding]
    unchanged: list[Finding]

    @property
    def added_count(self) -> int:
        return len(self.added)

    @property
    def resolved_count(self) -> int:
        return len(self.resolved)

    @property
    def unchanged_count(self) -> int:
        return len(self.unchanged)
