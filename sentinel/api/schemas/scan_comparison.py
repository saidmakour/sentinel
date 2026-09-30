from pydantic import BaseModel


class FindingComparisonSchema(BaseModel):
    dependency_name: str
    dependency_version: str
    identifier: str
    severity: str
    summary: str


class ScanComparisonSchema(BaseModel):
    previous_scan_id: int
    current_scan_id: int

    added: list[FindingComparisonSchema]
    resolved: list[FindingComparisonSchema]
    unchanged: list[FindingComparisonSchema]

    added_count: int
    resolved_count: int
    unchanged_count: int
