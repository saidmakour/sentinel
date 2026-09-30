from __future__ import annotations

from sentinel.doctor.checks.base import BaseDoctorCheck
from sentinel.dto.doctor_check import DoctorCheck
from sentinel.enums.doctor_status import DoctorStatus
from sentinel.enums.provider import Provider
from sentinel.providers.registry import ProviderRegistry


class ProviderCheck(BaseDoctorCheck):
    def __init__(
        self,
        provider: Provider,
        registry: ProviderRegistry | None = None,
    ) -> None:
        self.provider = provider
        self.registry = registry or ProviderRegistry()

    def run(
        self,
    ) -> list[DoctorCheck]:

        if self.registry.is_available(
            self.provider,
        ):
            return [
                DoctorCheck(
                    name=f"provider.{self.provider.name}",
                    status=DoctorStatus.PASS,
                    message=(f"Provider {self.provider.name} is available"),
                )
            ]

        return [
            DoctorCheck(
                name=f"provider.{self.provider.name}",
                status=DoctorStatus.FAIL,
                message="Provider unavailable",
            )
        ]
