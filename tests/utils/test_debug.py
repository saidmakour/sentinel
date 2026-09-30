# tests/utils/test_debug.py

from unittest.mock import Mock

from sentinel.utils.debug import Debug


def test_enabled_returns_true_when_debug_is_enabled(monkeypatch) -> None:
    monkeypatch.setattr("sentinel.utils.debug.settings.debug", True)

    assert Debug.enabled() is True


def test_enabled_returns_false_when_debug_is_disabled(monkeypatch) -> None:
    monkeypatch.setattr("sentinel.utils.debug.settings.debug", False)

    assert Debug.enabled() is False


def test_log_calls_secho_when_debug_is_enabled(monkeypatch) -> None:
    secho_mock = Mock()
    monkeypatch.setattr("sentinel.utils.debug.settings.debug", True)
    monkeypatch.setattr("sentinel.utils.debug.typer.secho", secho_mock)

    Debug.log("hello")

    secho_mock.assert_called_once_with(
        "[DEBUG] hello",
        fg="bright_black",
    )


def test_log_does_not_call_secho_when_debug_is_disabled(monkeypatch) -> None:
    secho_mock = Mock()
    monkeypatch.setattr("sentinel.utils.debug.settings.debug", False)
    monkeypatch.setattr("sentinel.utils.debug.typer.secho", secho_mock)

    Debug.log("hello")

    secho_mock.assert_not_called()


def test_info_calls_secho_when_debug_is_enabled(monkeypatch) -> None:
    secho_mock = Mock()
    monkeypatch.setattr("sentinel.utils.debug.settings.debug", True)
    monkeypatch.setattr("sentinel.utils.debug.typer.secho", secho_mock)

    Debug.info("hello")

    secho_mock.assert_called_once_with(
        "[INFO] hello",
        fg="bright_blue",
    )


def test_success_calls_secho_when_debug_is_enabled(monkeypatch) -> None:
    secho_mock = Mock()
    monkeypatch.setattr("sentinel.utils.debug.settings.debug", True)
    monkeypatch.setattr("sentinel.utils.debug.typer.secho", secho_mock)

    Debug.success("done")

    secho_mock.assert_called_once_with(
        "[ OK ] done",
        fg="green",
    )


def test_warning_calls_secho_when_debug_is_enabled(monkeypatch) -> None:
    secho_mock = Mock()
    monkeypatch.setattr("sentinel.utils.debug.settings.debug", True)
    monkeypatch.setattr("sentinel.utils.debug.typer.secho", secho_mock)

    Debug.warning("careful")

    secho_mock.assert_called_once_with(
        "[WARN] careful",
        fg="yellow",
    )


def test_error_calls_secho_when_debug_is_enabled(monkeypatch) -> None:
    secho_mock = Mock()
    monkeypatch.setattr("sentinel.utils.debug.settings.debug", True)
    monkeypatch.setattr("sentinel.utils.debug.typer.secho", secho_mock)

    Debug.error("boom")

    secho_mock.assert_called_once_with(
        "[ERR ] boom",
        fg="red",
    )
