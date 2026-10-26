import sentinel.models as models


def test_models_exports_match_public_api() -> None:
    assert models.__all__ == [
        "Application",
        "Repository",
        "Scan",
        "Dependency",
        "Finding",
        "Vulnerability",
    ]

    for name in models.__all__:
        assert hasattr(models, name)
