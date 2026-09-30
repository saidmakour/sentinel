from unittest.mock import MagicMock

import pytest

from sentinel.enums.git_auth_method import GitAuthMethod
from sentinel.sources.git.authentication.base import GitAuthenticator
from sentinel.sources.git.authentication.factory import GitAuthenticatorFactory


def test_factory_can_be_created() -> None:
    factory = GitAuthenticatorFactory()

    assert factory is not None


@pytest.mark.parametrize(
    "auth_method",
    [
        GitAuthMethod.NONE,
        GitAuthMethod.HTTPS,
        GitAuthMethod.SSH,
    ],
)
def test_factory_creates_authenticator(
    auth_method: GitAuthMethod,
) -> None:
    factory = GitAuthenticatorFactory()

    authenticator = factory.create(
        auth_method,
    )

    assert isinstance(
        authenticator,
        GitAuthenticator,
    )


def test_factory_returns_provided_authenticator() -> None:
    no_auth = MagicMock(spec=GitAuthenticator)
    https = MagicMock(spec=GitAuthenticator)
    ssh = MagicMock(spec=GitAuthenticator)

    factory = GitAuthenticatorFactory(
        no_auth=no_auth,
        https=https,
        ssh=ssh,
    )

    assert (
        factory.create(
            GitAuthMethod.NONE,
        )
        is no_auth
    )

    assert (
        factory.create(
            GitAuthMethod.HTTPS,
        )
        is https
    )

    assert (
        factory.create(
            GitAuthMethod.SSH,
        )
        is ssh
    )


def test_factory_raises_for_unknown_auth_method() -> None:
    factory = GitAuthenticatorFactory()

    with pytest.raises(
        KeyError,
    ):
        factory.create(
            "unknown",  # type: ignore[arg-type]
        )
