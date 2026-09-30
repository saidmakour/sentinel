from pathlib import Path

from sentinel.config.settings import settings
from sentinel.doctor.checks.base import BaseDoctorCheck
from sentinel.doctor.checks.database import DatabaseCheck
from sentinel.doctor.checks.directories import DirectoryCheck
from sentinel.doctor.checks.env import EnvCheck
from sentinel.doctor.checks.provider import ProviderCheck
from sentinel.doctor.checks.version import VersionCheck
from sentinel.dto.doctor_check import DoctorCheck
from sentinel.dto.doctor_report import DoctorReport
from sentinel.enums.provider import Provider
from sentinel.providers.registry import ProviderRegistry


class DoctorService:
    def __init__(
        self,
        checks: list[BaseDoctorCheck] | None = None,
        provider_registry: ProviderRegistry | None = None,
    ) -> None:
        self.provider_registry = provider_registry or ProviderRegistry()

        self.checks = checks or [
            VersionCheck(),
            DatabaseCheck(),
            DirectoryCheck(
                directories={
                    "database": Path(settings.database_dir),
                    "logs": Path(settings.logs_dir),
                    "workspace": Path(settings.workspace),
                    "reports": Path(settings.report_path),
                    "cache": Path(settings.cache),
                },
            ),
            EnvCheck(),
            ProviderCheck(
                Provider.OSV,
                registry=self.provider_registry,
            ),
            ProviderCheck(
                Provider.NVD,
                registry=self.provider_registry,
            ),
            ProviderCheck(
                Provider.GHSA,
                registry=self.provider_registry,
            ),
        ]

    def run(
        self,
    ) -> DoctorReport:

        results: list[DoctorCheck] = []

        for check in self.checks:
            results.extend(
                check.run(),
            )

        return DoctorReport(
            checks=results,
        )
