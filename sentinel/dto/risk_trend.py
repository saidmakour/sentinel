from dataclasses import dataclass


@dataclass(slots=True)
class RiskTrend:
    current_score: int

    previous_score: int | None

    delta: int

    trend: str
