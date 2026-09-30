from __future__ import annotations

from urllib.parse import urlparse


class GitRemoteParser:
    """
    Parses Git remote URLs.
    """

    @staticmethod
    def extract_host(
        remote_url: str,
    ) -> str | None:
        """
        Extract and normalize the host from a Git remote URL.

        Supported formats include:

        - https://gitlab.example.com/group/project.git
        - http://gitlab.example.com/group/project.git
        - ssh://git@gitlab.example.com/group/project.git
        - git@gitlab.example.com:group/project.git
        """

        value = remote_url.strip()

        if not value:
            return None

        if "://" in value:
            parsed = urlparse(
                value,
            )

            if parsed.hostname is None:
                return None

            return parsed.hostname.lower()

        if ":" not in value:
            return None

        host = value.split(
            ":",
            1,
        )[0]

        if "@" in host:
            host = host.split(
                "@",
                1,
            )[1]

        host = host.strip()

        return host.lower() or None
