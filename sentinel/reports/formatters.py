from datetime import datetime


def format_datetime(
    value: datetime | None,
) -> str:

    if value is None:
        return "N/A"

    return value.strftime(
        "%Y-%m-%d %H:%M:%S UTC",
    )


def format_duration(
    seconds: int | None,
) -> str:

    if seconds is None:
        return "N/A"

    minutes, seconds = divmod(
        seconds,
        60,
    )

    if minutes:
        return f"{minutes}m {seconds}s"

    return f"{seconds}s"
