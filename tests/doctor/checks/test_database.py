from unittest.mock import MagicMock

from sentinel.doctor.checks.database import DatabaseCheck
from sentinel.dto.doctor_check import DoctorCheck
from sentinel.enums.doctor_status import DoctorStatus


def create_check(
    monkeypatch,
) -> tuple[
    DatabaseCheck,
    MagicMock,
    MagicMock,
]:
    session = MagicMock()

    session_factory = MagicMock(
        return_value=session,
    )

    monkeypatch.setattr(
        "sentinel.doctor.checks.database.SessionLocal",
        session_factory,
    )

    check = DatabaseCheck()

    return (
        check,
        session_factory,
        session,
    )


def test_database_check_can_be_created() -> None:
    check = DatabaseCheck()

    assert check is not None


def test_run_returns_doctor_check(
    monkeypatch,
) -> None:
    (
        check,
        _,
        _,
    ) = create_check(
        monkeypatch,
    )

    results = check.run()
    result = results[0]

    assert isinstance(
        result,
        DoctorCheck,
    )


def test_run_returns_pass_when_database_is_available(
    monkeypatch,
) -> None:
    (
        check,
        session_factory,
        session,
    ) = create_check(
        monkeypatch,
    )

    results = check.run()
    result = results[0]

    session_factory.assert_called_once_with()

    session.execute.assert_called_once()

    assert result.status == DoctorStatus.PASS


def test_run_returns_database_name(
    monkeypatch,
) -> None:
    (
        check,
        _,
        _,
    ) = create_check(
        monkeypatch,
    )

    results = check.run()
    result = results[0]

    assert result.name == "Database"


def test_run_returns_database_message(
    monkeypatch,
) -> None:
    (
        check,
        _,
        _,
    ) = create_check(
        monkeypatch,
    )

    results = check.run()
    result = results[0]

    assert "database" in result.message.lower()


def test_run_returns_fail_when_connection_fails(
    monkeypatch,
) -> None:
    (
        check,
        _,
        session,
    ) = create_check(
        monkeypatch,
    )

    session.execute.side_effect = RuntimeError(
        "Connection failed",
    )

    results = check.run()
    result = results[0]

    assert result.status == DoctorStatus.FAIL

    assert "Connection failed" in result.message


def test_run_closes_session(
    monkeypatch,
) -> None:
    (
        check,
        _,
        session,
    ) = create_check(
        monkeypatch,
    )

    check.run()

    session.close.assert_called_once_with()


def test_run_closes_session_when_connection_fails(
    monkeypatch,
) -> None:
    (
        check,
        _,
        session,
    ) = create_check(
        monkeypatch,
    )

    session.execute.side_effect = RuntimeError(
        "Boom",
    )

    check.run()

    session.close.assert_called_once_with()
