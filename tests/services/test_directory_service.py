from unittest.mock import MagicMock

from sentinel.services.directory_service import DirectoryService


def test_ensure_structure_creates_all_directories(
    monkeypatch,
) -> None:
    directories = [
        "/tmp/database",
        "/tmp/logs",
        "/tmp/workspace",
        "/tmp/reports",
        "/tmp/tests",
        "/tmp/cache",
        "/tmp/export",
    ]

    settings = MagicMock()

    settings.database_dir = directories[0]
    settings.logs_dir = directories[1]
    settings.workspace = directories[2]
    settings.report_path = directories[3]
    settings.tests = directories[4]
    settings.cache = directories[5]
    settings.export_path = directories[6]

    monkeypatch.setattr(
        "sentinel.services.directory_service.settings",
        settings,
    )

    path_instances = []

    def create_path(directory):
        path = MagicMock()
        path_instances.append(
            (
                directory,
                path,
            )
        )
        return path

    monkeypatch.setattr(
        "sentinel.services.directory_service.Path",
        create_path,
    )

    DirectoryService.ensure_structure()

    assert len(path_instances) == 7

    assert [directory for directory, _ in path_instances] == directories

    for _, path in path_instances:
        path.mkdir.assert_called_once_with(
            parents=True,
            exist_ok=True,
        )
