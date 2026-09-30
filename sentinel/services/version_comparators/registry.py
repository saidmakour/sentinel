from sentinel.enums.ecosystem import Ecosystem
from sentinel.services.version_comparators.base import BaseVersionComparator


class VersionComparatorRegistry:
    def __init__(
        self,
        comparators: dict[
            Ecosystem,
            BaseVersionComparator,
        ]
        | None = None,
    ) -> None:
        self._comparators = comparators or {}

    @property
    def comparators(
        self,
    ) -> dict[Ecosystem, BaseVersionComparator]:
        return dict(self._comparators)

    def register(
        self,
        ecosystem: Ecosystem,
        comparator: BaseVersionComparator,
    ) -> None:
        self._comparators[ecosystem] = comparator

    def get(
        self,
        ecosystem: Ecosystem,
    ) -> BaseVersionComparator | None:
        return self._comparators.get(ecosystem)

    def supports(
        self,
        ecosystem: Ecosystem,
    ) -> bool:
        return ecosystem in self._comparators
