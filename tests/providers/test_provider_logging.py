from unittest.mock import Mock

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.providers.executor import ProviderExecutor


def make_dependency() -> ScannedDependency:
    return ScannedDependency(
        name="requests",
        version="2.32.0",
        ecosystem="PyPI",
        source="requirements.txt",
    )


def make_provider(
    name: str = "OSV",
) -> Mock:
    provider = Mock()
    provider.name = name
    provider.scan.return_value = []

    return provider


def test_execute_logs_no_providers(
    caplog,
) -> None:
    executor = ProviderExecutor()

    dependency = make_dependency()

    with caplog.at_level("DEBUG"):
        result = executor.execute(
            dependency,
            [],
        )

    assert result == []

    assert "No providers available" in caplog.text

    assert "dependency=requests" in caplog.text


def test_execute_logs_provider_execution(
    caplog,
) -> None:
    executor = ProviderExecutor()

    dependency = make_dependency()
    provider = make_provider()

    with caplog.at_level("DEBUG"):
        executor.execute(
            dependency,
            [provider],
        )

    assert "Executing providers" in caplog.text

    assert "Provider execution completed" in caplog.text


def test_execute_logs_cache_miss(
    caplog,
) -> None:
    executor = ProviderExecutor()

    dependency = make_dependency()
    provider = make_provider()

    with caplog.at_level("DEBUG"):
        executor.execute(
            dependency,
            [provider],
        )

    assert "Provider cache miss" in caplog.text


def test_execute_logs_provider_completed(
    caplog,
) -> None:
    executor = ProviderExecutor()

    dependency = make_dependency()
    provider = make_provider()

    with caplog.at_level("DEBUG"):
        executor.execute(
            dependency,
            [provider],
        )

    assert "Provider completed" in caplog.text

    assert "vulnerabilities=0" in caplog.text


def test_execute_logs_provider_failure(
    caplog,
) -> None:
    executor = ProviderExecutor()

    dependency = make_dependency()
    provider = make_provider()

    provider.scan.side_effect = RuntimeError(
        "Provider failure",
    )

    with caplog.at_level("ERROR"):
        result = executor.execute(
            dependency,
            [provider],
        )

    assert result == []

    assert "Provider failed" in caplog.text

    assert "dependency=requests" in caplog.text

    assert "RuntimeError: Provider failure" in caplog.text


def test_execute_logs_cache_hit(
    caplog,
) -> None:
    executor = ProviderExecutor()

    dependency = make_dependency()
    provider = make_provider()

    executor.cache.set(
        provider.name,
        dependency,
        [],
    )

    with caplog.at_level("DEBUG"):
        executor.execute(
            dependency,
            [provider],
        )

    assert "Provider cache hit" in caplog.text

    provider.scan.assert_not_called()
