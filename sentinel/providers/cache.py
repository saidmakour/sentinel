from copy import deepcopy
from threading import Lock

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.provider import Provider


class ProviderCache:
    def __init__(self) -> None:
        self._cache: dict[
            tuple[Provider, str, str, str],
            list[VulnerabilityInfo],
        ] = {}
        self._lock = Lock()

    def _make_key(
        self,
        provider: Provider,
        dependency: ScannedDependency,
    ) -> tuple[Provider, str, str, str]:
        return (
            provider,
            dependency.ecosystem,
            dependency.name.lower(),
            dependency.version,
        )

    def get(
        self,
        provider: Provider,
        dependency: ScannedDependency,
    ) -> list[VulnerabilityInfo] | None:

        with self._lock:
            cached = self._cache.get(
                self._make_key(
                    provider,
                    dependency,
                )
            )

        return deepcopy(cached) if cached is not None else None

    def set(
        self,
        provider: Provider,
        dependency: ScannedDependency,
        findings: list[VulnerabilityInfo],
    ) -> None:
        with self._lock:
            self._cache[
                self._make_key(
                    provider,
                    dependency,
                )
            ] = deepcopy(findings)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
