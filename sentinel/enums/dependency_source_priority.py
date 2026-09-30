from enum import IntEnum


class DependencySourcePriority(IntEnum):
    """
    Lower value = higher priority.
    """

    # Lock files
    LOCK_FILE = 10

    # Version manifests
    MANIFEST = 20

    # Meta
    METADATA = 30
