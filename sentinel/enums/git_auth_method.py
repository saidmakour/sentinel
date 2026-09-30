from enum import StrEnum


class GitAuthMethod(StrEnum):
    NONE = "none"
    HTTPS = "https"
    SSH = "ssh"
