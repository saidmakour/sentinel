import logging

from sentinel.log.formatter import SentinelLogFormatter


def test_sentinel_log_formatter_formats_log_record() -> None:
    formatter = SentinelLogFormatter()

    record = logging.LogRecord(
        name="sentinel.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Test message",
        args=(),
        exc_info=None,
    )

    result = formatter.format(record)

    assert "INFO" in result
    assert "sentinel.test" in result
    assert "Test message" in result
    assert "|" in result


def test_sentinel_log_formatter_uses_expected_format() -> None:
    formatter = SentinelLogFormatter()

    assert formatter._fmt == (
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )

    assert formatter.datefmt == "%Y-%m-%d %H:%M:%S"
