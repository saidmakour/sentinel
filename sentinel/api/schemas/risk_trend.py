from pydantic import BaseModel


class RiskTrendSchema(BaseModel):
    current_score: int

    previous_score: int | None

    delta: int

    trend: str
