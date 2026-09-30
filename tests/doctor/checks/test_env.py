from pathlib import Path

from sentinel.doctor.checks.env import EnvCheck
from sentinel.dto.doctor_check import DoctorCheck
from sentinel.enums.doctor_status import DoctorStatus


def test_env_check_can_be_created(
    tmp_path: Path,
) -> None:
    env_path = tmp_path / ".env"

    check = EnvCheck(
        env_path=env_path,
    )

    assert check is not None


def test_run_returns_doctor_check(
    tmp_path: Path,
) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text(
        "TEST=value",
        encoding="utf-8",
    )

    check = EnvCheck(
        env_path=env_path,
    )

    result = check.run()

    assert isinstance(
        result[0],
        DoctorCheck,
    )


def test_run_returns_pass_when_env_file_exists(
    tmp_path: Path,
) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text(
        "TEST=value",
        encoding="utf-8",
    )

    check = EnvCheck(
        env_path=env_path,
    )

    result = check.run()

    assert result[0].name == ".env"
    assert result[0].status == DoctorStatus.PASS
    assert result[0].message == f"{env_path} available"


def test_run_returns_fail_when_env_file_does_not_exist(
    tmp_path: Path,
) -> None:
    env_path = tmp_path / ".env"

    check = EnvCheck(
        env_path=env_path,
    )

    result = check.run()

    assert result[0].name == ".env"
    assert result[0].status == DoctorStatus.FAIL
    assert result[0].message == f"File not found: {env_path}"


def test_run_returns_fail_when_env_path_is_directory(
    tmp_path: Path,
) -> None:
    env_path = tmp_path / ".env"
    env_path.mkdir()

    check = EnvCheck(
        env_path=env_path,
    )

    result = check.run()

    assert result[0].name == ".env"
    assert result[0].status == DoctorStatus.FAIL
    assert result[0].message == f"Not a file: {env_path}"


def test_run_returns_fail_when_env_file_cannot_be_read(
    tmp_path: Path,
    monkeypatch,
) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text(
        "TEST=value",
        encoding="utf-8",
    )

    def raise_os_error(
        *args,
        **kwargs,
    ) -> str:
        raise OSError("Permission denied")

    monkeypatch.setattr(
        Path,
        "read_text",
        raise_os_error,
    )

    check = EnvCheck(
        env_path=env_path,
    )

    result = check.run()

    assert result[0].name == ".env"
    assert result[0].status == DoctorStatus.FAIL
    assert result[0].message == "Permission denied"


def test_env_check_uses_default_env_path(
    monkeypatch,
    tmp_path: Path,
) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text(
        "TEST=value",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)

    check = EnvCheck()

    result = check.run()

    assert result[0].name == ".env"
    assert result[0].status == DoctorStatus.PASS
