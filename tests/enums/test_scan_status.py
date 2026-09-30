from enum import StrEnum

from sentinel.enums.scan_status import ScanStatus


def test_scan_status_is_str_enum():
    assert issubclass(ScanStatus, StrEnum)


def test_scan_status_values():
    assert ScanStatus.STARTED.value == "started"
    assert ScanStatus.SUCCESS.value == "success"
    assert ScanStatus.FAILED.value == "failed"


def test_scan_status_string_behavior():
    assert str(ScanStatus.STARTED) == "started"
    assert str(ScanStatus.SUCCESS) == "success"
    assert str(ScanStatus.FAILED) == "failed"

    assert set(ScanStatus.__members__.keys()) == {
        "STARTED",
        "SUCCESS",
        "FAILED",
    }
