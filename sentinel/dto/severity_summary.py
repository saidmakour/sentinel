from dataclasses import dataclass


@dataclass(slots=True)
class SeveritySummary:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0

    @property
    def total(self) -> int:
        return (
            self.critical + self.high + self.medium + self.low + self.unknown
        )
