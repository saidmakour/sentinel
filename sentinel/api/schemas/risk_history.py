from datetime import datetime

from pydantic import BaseModel


class RiskHistoryPointSchema(BaseModel):
    scan_id: int
    date: datetime

    critical: int
    high: int
    medium: int
    low: int

    risk_score: int
