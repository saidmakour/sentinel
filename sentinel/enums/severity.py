from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @property
    def priority(self) -> int:
        match self:
            case Severity.UNKNOWN:
                return 0
            case Severity.LOW:
                return 1
            case Severity.MEDIUM:
                return 2
            case Severity.HIGH:
                return 3
            case Severity.CRITICAL:
                return 4
