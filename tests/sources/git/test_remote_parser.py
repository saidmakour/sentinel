import pytest

from sentinel.sources.git.remote_parser import GitRemoteParser


@pytest.mark.parametrize(
    ("remote_url", "expected"),
    [
        (
            "https://gitlab.example.com/group/project.git",
            "gitlab.example.com",
        ),
        (
            "http://gitlab.example.com/group/project.git",
            "gitlab.example.com",
        ),
        (
            "ssh://git@gitlab.example.com/group/project.git",
            "gitlab.example.com",
        ),
        (
            "git@gitlab.example.com:group/project.git",
            "gitlab.example.com",
        ),
        (
            "GIT@GitLab.Example.COM:group/project.git",
            "gitlab.example.com",
        ),
    ],
)
def test_extract_host(
    remote_url,
    expected,
) -> None:
    assert (
        GitRemoteParser.extract_host(
            remote_url,
        )
        == expected
    )


@pytest.mark.parametrize(
    "remote_url",
    [
        "",
        "   ",
        "not-a-valid-url",
    ],
)
def test_extract_host_returns_none_for_invalid_url(
    remote_url,
) -> None:
    assert (
        GitRemoteParser.extract_host(
            remote_url,
        )
        is None
    )
