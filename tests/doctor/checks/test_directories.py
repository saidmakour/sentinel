from pathlib import Path

from sentinel.doctor.checks.directories import DirectoryCheck
from sentinel.dto.doctor_check import DoctorCheck
from sentinel.enums.doctor_status import DoctorStatus


def test_directory_check_can_be_created(
    tmp_path: Path,
) -> None:
    check = DirectoryCheck(
        directories={
            "workspace": tmp_path,
        },
    )

    assert check is not None


def test_run_returns_list_of_doctor_checks(
    tmp_path: Path,
) -> None:
    check = DirectoryCheck(
        directories={
            "workspace": tmp_path,
        },
    )

    result = check.run()

    assert isinstance(
        result,
        list,
    )

    assert len(result) == 1

    assert isinstance(
        result[0],
        DoctorCheck,
    )


def test_run_returns_pass_for_existing_directory(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    check = DirectoryCheck(
        directories={
            "workspace": workspace,
        },
    )

    results = check.run()

    assert len(results) == 1

    result = results[0]

    assert result.name == "workspace"
    assert result.status == DoctorStatus.PASS
    assert result.message == str(workspace)


def test_run_returns_fail_for_missing_directory(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"

    check = DirectoryCheck(
        directories={
            "workspace": workspace,
        },
    )

    results = check.run()

    assert len(results) == 1

    result = results[0]

    assert result.name == "workspace"
    assert result.status == DoctorStatus.FAIL
    assert result.message == (f"Directory not found: {workspace}")


def test_run_returns_one_result_per_directory(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    reports = tmp_path / "reports"
    cache = tmp_path / "cache"

    workspace.mkdir()
    reports.mkdir()
    cache.mkdir()

    check = DirectoryCheck(
        directories={
            "workspace": workspace,
            "reports": reports,
            "cache": cache,
        },
    )

    results = check.run()

    assert len(results) == 3

    assert [result.name for result in results] == [
        "workspace",
        "reports",
        "cache",
    ]

    assert all(result.status == DoctorStatus.PASS for result in results)


def test_run_handles_mixed_directory_states(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    reports = tmp_path / "reports"

    workspace.mkdir()

    check = DirectoryCheck(
        directories={
            "workspace": workspace,
            "reports": reports,
        },
    )

    results = check.run()

    assert len(results) == 2

    assert results[0].name == "workspace"
    assert results[0].status == DoctorStatus.PASS

    assert results[1].name == "reports"
    assert results[1].status == DoctorStatus.FAIL


def test_run_returns_empty_list_for_no_directories() -> None:
    check = DirectoryCheck(
        directories={},
    )

    results = check.run()

    assert results == []


def test_run_returns_fail_for_file_instead_of_directory(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace.txt"
    workspace.write_text(
        "test",
        encoding="utf-8",
    )

    check = DirectoryCheck(
        directories={
            "workspace": workspace,
        },
    )

    results = check.run()

    assert len(results) == 1

    result = results[0]

    assert result.name == "workspace"
    assert result.status == DoctorStatus.FAIL
    assert result.message == (f"Directory not found: {workspace}")
