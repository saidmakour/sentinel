import pytest

from sentinel.sources.git.authentication.base import GitAuthenticator
from sentinel.sources.git.authentication.context import GitAuthContext


def test_git_authenticator_is_abstract() -> None:
    with pytest.raises(
        TypeError,
    ):
        GitAuthenticator()


class TestAuthenticator(
    GitAuthenticator,
):
    def prepare(
        self,
        credentials=None,
    ) -> GitAuthContext:
        return GitAuthContext()


def test_git_authenticator_can_be_implemented() -> None:
    authenticator = TestAuthenticator()

    context = authenticator.prepare()

    assert isinstance(
        context,
        GitAuthContext,
    )
