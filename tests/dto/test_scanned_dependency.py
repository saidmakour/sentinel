from sentinel.dto.scanned_dependency import ScannedDependency


def test_scanned_dependency_creation():
    dependency = ScannedDependency(
        name="django",
        version="5.0.6",
        ecosystem="pypi",
        source="requirements.txt",
    )

    assert dependency.name == "django"
    assert dependency.version == "5.0.6"
    assert dependency.ecosystem == "pypi"
    assert dependency.source == "requirements.txt"
    assert dependency.priority == 100


def test_scanned_dependency_custom_priority():
    dependency = ScannedDependency(
        name="requests",
        version="2.32.0",
        ecosystem="pypi",
        source="poetry.lock",
        priority=10,
    )

    assert dependency.priority == 10
