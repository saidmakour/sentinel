from sentinel.enums.severity import Severity


def severity_from_cvss(
    score: float | None,
) -> Severity:
    """
    Convert a CVSS score into a Severity.
    """
    if score is None:
        return Severity.UNKNOWN

    if score >= 9.0:
        return Severity.CRITICAL

    if score >= 7.0:
        return Severity.HIGH

    if score >= 4.0:
        return Severity.MEDIUM

    return Severity.LOW
