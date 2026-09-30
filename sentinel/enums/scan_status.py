from enum import StrEnum


class ScanStatus(StrEnum):
    STARTED = "started"
    SUCCESS = "success"
    FAILED = "failed"
