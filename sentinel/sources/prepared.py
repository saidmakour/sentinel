from dataclasses import dataclass
from pathlib import Path

from sentinel.enums.source_type import SourceType


@dataclass(frozen=True)
class PreparedSource:
    path: Path
    source_type: SourceType
    reference: str
    branch: str | None = None
    commit: str | None = None
