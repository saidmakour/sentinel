from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class RiskHistoryPoint:
    scan_id: int
    date: datetime

    critical: int
    high: int
    medium: int
    low: int

    risk_score: int
