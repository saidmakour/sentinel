from enum import StrEnum

from sentinel.enums.provider import Provider


def test_provider_is_str_enum():
    assert issubclass(Provider, StrEnum)


def test_provider_values():
    # Remplace les membres ci-dessous par les vrais membres de ton enum
    assert Provider.OSV.value == "OSV"
    assert Provider.NVD.value == "NVD"
    # assert Provider.GITHUB.value == "github"
