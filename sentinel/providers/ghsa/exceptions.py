class GHSAError(Exception):
    """Base exception for GHSA."""


class GHSARequestError(GHSAError):
    """Network error."""


class GHSAResponseError(GHSAError):
    """Invalid response."""
