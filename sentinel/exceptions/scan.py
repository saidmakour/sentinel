# sentinel/exceptions/scan.py


class ScanNotFoundError(Exception):
    """Raised when a scan does not exist."""


class NoScansFoundError(ValueError):
    """No scans found"""
