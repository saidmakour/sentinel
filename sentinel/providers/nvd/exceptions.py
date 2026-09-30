# sentinel/providers/nvd/exceptions.py


class NVDError(Exception):
    """Base exception for NVD."""


class NVDRequestError(NVDError):
    """Network error."""


class NVDResponseError(NVDError):
    """Invalid response."""
