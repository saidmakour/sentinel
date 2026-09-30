class KEVError(Exception):
    """Base KEV exception."""


class KEVRequestError(KEVError):
    """Network error while querying KEV."""


class KEVResponseError(KEVError):
    """Invalid KEV response."""


class VulnCheckKEVRequestError(Exception):
    """
    Raised when a VulnCheck KEV request fails.
    """


class VulnCheckKEVResponseError(Exception):
    """
    Raised when a VulnCheck KEV response is invalid.
    """
