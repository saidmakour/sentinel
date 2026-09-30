from pathlib import Path

from sentinel.config.settings import settings


class DirectoryService:
    @staticmethod
    def ensure_structure() -> None:
        """Create the Sentinel working directories if they do not exist."""
        directories = [
            settings.database_dir,
            settings.logs_dir,
            settings.workspace,
            settings.report_path,
            settings.tests,
            settings.cache,
            settings.export_path,
        ]

        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
