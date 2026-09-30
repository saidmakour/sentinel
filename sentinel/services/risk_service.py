from sentinel.enums.severity import Severity

_CRITICAL_WEIGHT = 10
_HIGH_WEIGHT = 5
_MEDIUM_WEIGHT = 2
_LOW_WEIGHT = 1


class RiskService:
    """
    Handles security risk calculations.
    """

    def calculate(
        self,
        counts: dict[str, int],
    ) -> tuple[int, int, int, int, int]:
        """
        Calculate risk metrics from severity counts.
        """

        critical = counts.get(
            Severity.CRITICAL.value,
            0,
        )

        high = counts.get(
            Severity.HIGH.value,
            0,
        )

        medium = counts.get(
            Severity.MEDIUM.value,
            0,
        )

        low = counts.get(
            Severity.LOW.value,
            0,
        )

        score = (
            critical * _CRITICAL_WEIGHT
            + high * _HIGH_WEIGHT
            + medium * _MEDIUM_WEIGHT
            + low * _LOW_WEIGHT
        )

        return (
            critical,
            high,
            medium,
            low,
            score,
        )
