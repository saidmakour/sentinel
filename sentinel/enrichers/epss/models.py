from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class EPSSScore:
    cve: str
    score: float
    percentile: float


@dataclass(slots=True, frozen=True)
class EPSSResponse:
    scores: list[EPSSScore]
