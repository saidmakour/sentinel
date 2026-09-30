from dataclasses import asdict
from dataclasses import astuple

import pytest

from sentinel.dto.finding_statistics import FindingStatistics


@pytest.fixture
def sample_statistics():
    """Fixture fournissant une instance de base pour les tests."""
    return FindingStatistics(
        dependency_count=10,
        occurrence_count=25,
        unique_vulnerability_count=5,
        unique_identifier_count=15,
        provider_count={"npm": 5, "pypi": 3},
        dependency_occurrence_count={"lodash": 10, "requests": 5},
        duplicated_identifier_count=2,
    )


class TestFindingStatisticsInstantiation:
    """Tests d'initialisation de la dataclass."""

    def test_create_with_valid_values(self):
        """Test de création avec des valeurs valides."""
        fs = FindingStatistics(
            dependency_count=10,
            occurrence_count=25,
            unique_vulnerability_count=5,
            unique_identifier_count=15,
            provider_count={"npm": 5, "pypi": 3},
            dependency_occurrence_count={"lodash": 10, "requests": 5},
            duplicated_identifier_count=2,
        )
        assert fs.dependency_count == 10
        assert fs.occurrence_count == 25
        assert fs.unique_vulnerability_count == 5
        assert fs.unique_identifier_count == 15
        assert fs.provider_count == {"npm": 5, "pypi": 3}
        assert fs.dependency_occurrence_count == {"lodash": 10, "requests": 5}
        assert fs.duplicated_identifier_count == 2

    def test_create_with_zero_values(self):
        """Test de création avec des valeurs à zéro."""
        fs = FindingStatistics(
            dependency_count=0,
            occurrence_count=0,
            unique_vulnerability_count=0,
            unique_identifier_count=0,
            provider_count={},
            dependency_occurrence_count={},
            duplicated_identifier_count=0,
        )
        assert fs.dependency_count == 0
        assert fs.provider_count == {}
        assert fs.duplicated_identifier_count == 0

    def test_create_with_large_values(self):
        """Test de création avec de grandes valeurs."""
        fs = FindingStatistics(
            dependency_count=1_000_000,
            occurrence_count=5_000_000,
            unique_vulnerability_count=500_000,
            unique_identifier_count=750_000,
            provider_count={"npm": 400_000, "pypi": 100_000},
            dependency_occurrence_count={"lodash": 200_000},
            duplicated_identifier_count=50_000,
        )
        assert fs.dependency_count == 1_000_000
        assert fs.occurrence_count == 5_000_000


class TestFindingStatisticsAttributes:
    """Tests des attributs et de leur mutabilité."""

    def test_attribute_access(self, sample_statistics):
        """Test d'accès aux attributs."""
        assert sample_statistics.dependency_count == 10
        assert sample_statistics.occurrence_count == 25
        assert sample_statistics.unique_vulnerability_count == 5
        assert sample_statistics.unique_identifier_count == 15
        assert sample_statistics.duplicated_identifier_count == 2

    def test_dict_attributes_are_mutable(self, sample_statistics):
        """Test que les attributs dict sont mutables."""
        sample_statistics.provider_count["maven"] = 7
        assert sample_statistics.provider_count == {
            "npm": 5,
            "pypi": 3,
            "maven": 7,
        }

        sample_statistics.dependency_occurrence_count["axios"] = 15
        assert "axios" in sample_statistics.dependency_occurrence_count

    def test_int_attributes_are_immutable(self, sample_statistics):
        """Test que les attributs int ne sont pas mutables (réassignation requise)."""
        # On ne peut pas modifier un int, on doit réassigner
        sample_statistics.dependency_count = 20
        assert sample_statistics.dependency_count == 20


class TestFindingStatisticsDataclassFeatures:
    """Tests des fonctionnalités dataclass."""

    def test_repr(self, sample_statistics):
        """Test de la méthode __repr__."""
        repr_str = repr(sample_statistics)
        assert "FindingStatistics" in repr_str
        assert "dependency_count=10" in repr_str
        assert "occurrence_count=25" in repr_str

    def test_eq(self):
        """Test de la méthode __eq__."""
        fs1 = FindingStatistics(
            dependency_count=10,
            occurrence_count=25,
            unique_vulnerability_count=5,
            unique_identifier_count=15,
            provider_count={"npm": 5},
            dependency_occurrence_count={"lodash": 10},
            duplicated_identifier_count=2,
        )
        fs2 = FindingStatistics(
            dependency_count=10,
            occurrence_count=25,
            unique_vulnerability_count=5,
            unique_identifier_count=15,
            provider_count={"npm": 5},
            dependency_occurrence_count={"lodash": 10},
            duplicated_identifier_count=2,
        )
        fs3 = FindingStatistics(
            dependency_count=11,
            occurrence_count=25,
            unique_vulnerability_count=5,
            unique_identifier_count=15,
            provider_count={"npm": 5},
            dependency_occurrence_count={"lodash": 10},
            duplicated_identifier_count=2,
        )

        assert fs1 == fs2
        assert fs1 != fs3

    def test_asdict(self, sample_statistics):
        """Test de conversion en dict."""
        fs_dict = asdict(sample_statistics)
        assert isinstance(fs_dict, dict)
        assert fs_dict["dependency_count"] == 10
        assert fs_dict["provider_count"] == {"npm": 5, "pypi": 3}
        assert fs_dict["dependency_occurrence_count"] == {
            "lodash": 10,
            "requests": 5,
        }

    def test_astuple(self, sample_statistics):
        """Test de conversion en tuple."""
        fs_tuple = astuple(sample_statistics)
        assert isinstance(fs_tuple, tuple)
        assert fs_tuple[0] == 10  # dependency_count
        assert fs_tuple[1] == 25  # occurrence_count

    def test_slots_defined(self):
        """Test que __slots__ est bien défini."""
        assert hasattr(FindingStatistics, "__slots__")
        assert "dependency_count" in FindingStatistics.__slots__
        assert "provider_count" in FindingStatistics.__slots__
        assert len(FindingStatistics.__slots__) == 7


class TestFindingStatisticsEdgeCases:
    """Tests des cas limites."""

    def test_negative_values(self):
        """Test avec des valeurs négatives (selon ta logique métier)."""
        fs = FindingStatistics(
            dependency_count=-1,
            occurrence_count=-5,
            unique_vulnerability_count=0,
            unique_identifier_count=0,
            provider_count={},
            dependency_occurrence_count={},
            duplicated_identifier_count=0,
        )
        assert fs.dependency_count == -1
        # Note: selon ta logique métier, tu pourrais vouloir valider que >= 0
