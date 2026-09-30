from dataclasses import dataclass

from sentinel.enums.ecosystem import Ecosystem


@dataclass(slots=True)
class ScannedDependency:
    name: str
    version: str
    ecosystem: Ecosystem
    source: str
    priority: int = 100
