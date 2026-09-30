from datetime import datetime

from pydantic import BaseModel


class ScanSummarySchema(BaseModel):
    id: int
    repository_id: int
    profile_name: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    duration: str | None
    dependency_count: int
    finding_count: int
