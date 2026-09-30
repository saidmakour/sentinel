from unittest.mock import Mock

import pytest

from sentinel.dto.finding_statistics import FindingStatistics
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.provider import Provider
from sentinel.services.finding_statistics_service import (
    FindingStatisticsService,
)


@pytest.fixture
def service():
    """Fixture pour le service à tester."""
    return FindingStatisticsService()


@pytest.fixture
def sample_dependency():
    """Fixture pour une dépendance scannée."""
    dep = Mock(spec=ScannedDependency)
    dep.name = "requests"
    dep.version = "2.28.0"
    dep.ecosystem = "pypi"
    return dep


@pytest.fixture
def sample_vulnerability():
    """Fixture pour une VulnerabilityInfo de base."""
    vuln = Mock(spec=VulnerabilityInfo)
    vuln.dependency_name = "requests"
    vuln.identifier = "CVE-2023-12345"
    vuln.sources = [Provider.OSV]
    return vuln


class TestFindingStatisticsServiceBuild:
    """Tests de la méthode build."""

    def test_build_with_empty_inputs(self, service):
        """Test avec des listes vides."""
        result = service.build(
            dependencies=[],
            findings=[],
        )

        assert isinstance(result, FindingStatistics)
        assert result.dependency_count == 0
        assert result.occurrence_count == 0
        assert result.unique_vulnerability_count == 0
        assert result.unique_identifier_count == 0
        assert result.provider_count == {}
        assert result.dependency_occurrence_count == {}
        assert result.duplicated_identifier_count == 0

    def test_build_with_single_dependency_single_finding(
        self, service, sample_dependency, sample_vulnerability
    ):
        """Test avec une seule dépendance et un seul finding."""
        result = service.build(
            dependencies=[sample_dependency],
            findings=[sample_vulnerability],
        )

        assert result.dependency_count == 1
        assert result.occurrence_count == 1
        assert result.unique_vulnerability_count == 1
        assert result.unique_identifier_count == 1
        assert result.provider_count == {"OSV": 1}
        assert result.dependency_occurrence_count == {"requests": 1}
        assert result.duplicated_identifier_count == 0

    def test_build_with_multiple_dependencies_no_findings(
        self, service, sample_dependency
    ):
        """Test avec plusieurs dépendances mais aucun finding."""
        dep2 = Mock(spec=ScannedDependency)
        dep2.name = "flask"
        dep2.version = "2.0.0"
        dep2.ecosystem = "pypi"

        result = service.build(
            dependencies=[sample_dependency, dep2],
            findings=[],
        )

        assert result.dependency_count == 2
        assert result.occurrence_count == 0
        assert result.unique_vulnerability_count == 0
        assert result.unique_identifier_count == 0
        assert result.provider_count == {}
        assert result.dependency_occurrence_count == {}
        assert result.duplicated_identifier_count == 0

    def test_build_with_multiple_findings_same_identifier(
        self, service, sample_dependency
    ):
        """Test avec plusieurs findings ayant le même identifier."""
        vuln1 = Mock(spec=VulnerabilityInfo)
        vuln1.dependency_name = "requests"
        vuln1.identifier = "CVE-2023-12345"
        vuln1.sources = [Provider.OSV]

        vuln2 = Mock(spec=VulnerabilityInfo)
        vuln2.dependency_name = "flask"
        vuln2.identifier = "CVE-2023-12345"  # Même identifier
        vuln2.sources = [Provider.GHSA]

        result = service.build(
            dependencies=[sample_dependency],
            findings=[vuln1, vuln2],
        )

        assert result.dependency_count == 1
        assert result.occurrence_count == 2
        assert (
            result.unique_vulnerability_count == 1
        )  # Un seul identifier unique
        assert result.unique_identifier_count == 1
        assert result.provider_count == {"OSV": 1, "GHSA": 1}
        assert result.dependency_occurrence_count == {
            "requests": 1,
            "flask": 1,
        }
        assert (
            result.duplicated_identifier_count == 1
        )  # CVE-2023-12345 apparaît 2 fois

    def test_build_with_multiple_findings_different_identifiers(
        self, service, sample_dependency
    ):
        """Test avec plusieurs findings ayant des identifiers différents."""
        vuln1 = Mock(spec=VulnerabilityInfo)
        vuln1.dependency_name = "requests"
        vuln1.identifier = "CVE-2023-11111"
        vuln1.sources = [Provider.OSV]

        vuln2 = Mock(spec=VulnerabilityInfo)
        vuln2.dependency_name = "requests"
        vuln2.identifier = "CVE-2023-22222"
        vuln2.sources = [Provider.OSV, Provider.GHSA]

        vuln3 = Mock(spec=VulnerabilityInfo)
        vuln3.dependency_name = "flask"
        vuln3.identifier = "CVE-2023-33333"
        vuln3.sources = [Provider.NVD]

        result = service.build(
            dependencies=[sample_dependency],
            findings=[vuln1, vuln2, vuln3],
        )

        assert result.dependency_count == 1
        assert result.occurrence_count == 3
        assert result.unique_vulnerability_count == 3
        assert result.unique_identifier_count == 3
        assert result.provider_count == {"OSV": 2, "GHSA": 1, "NVD": 1}
        assert result.dependency_occurrence_count == {
            "requests": 2,
            "flask": 1,
        }
        assert result.duplicated_identifier_count == 0

    def test_build_with_mixed_duplicated_identifiers(
        self, service, sample_dependency
    ):
        """Test avec certains identifiers dupliqués et d'autres non."""
        vuln1 = Mock(spec=VulnerabilityInfo)
        vuln1.dependency_name = "requests"
        vuln1.identifier = "CVE-DUP-001"
        vuln1.sources = [Provider.OSV]

        vuln2 = Mock(spec=VulnerabilityInfo)
        vuln2.dependency_name = "flask"
        vuln2.identifier = "CVE-DUP-001"  # Dupliqué
        vuln2.sources = [Provider.GHSA]

        vuln3 = Mock(spec=VulnerabilityInfo)
        vuln3.dependency_name = "django"
        vuln3.identifier = "CVE-UNIQUE-001"  # Unique
        vuln3.sources = [Provider.OSV]

        vuln4 = Mock(spec=VulnerabilityInfo)
        vuln4.dependency_name = "numpy"
        vuln4.identifier = "CVE-DUP-002"
        vuln4.sources = [Provider.NVD]

        vuln5 = Mock(spec=VulnerabilityInfo)
        vuln5.dependency_name = "pandas"
        vuln5.identifier = "CVE-DUP-002"  # Dupliqué
        vuln5.sources = [Provider.OSV]

        result = service.build(
            dependencies=[sample_dependency],
            findings=[vuln1, vuln2, vuln3, vuln4, vuln5],
        )

        assert result.occurrence_count == 5
        assert (
            result.unique_vulnerability_count == 3
        )  # CVE-DUP-001, CVE-UNIQUE-001, CVE-DUP-002
        assert result.unique_identifier_count == 3
        assert (
            result.duplicated_identifier_count == 2
        )  # CVE-DUP-001 et CVE-DUP-002

    def test_build_provider_count_across_multiple_providers(
        self, service, sample_dependency
    ):
        """Test du comptage des providers sur plusieurs findings."""
        vuln1 = Mock(spec=VulnerabilityInfo)
        vuln1.dependency_name = "requests"
        vuln1.identifier = "CVE-001"
        vuln1.sources = [Provider.OSV, Provider.GHSA, Provider.NVD]

        vuln2 = Mock(spec=VulnerabilityInfo)
        vuln2.dependency_name = "flask"
        vuln2.identifier = "CVE-002"
        vuln2.sources = [Provider.OSV]

        vuln3 = Mock(spec=VulnerabilityInfo)
        vuln3.dependency_name = "django"
        vuln3.identifier = "CVE-003"
        vuln3.sources = [Provider.GHSA, Provider.NVD]

        result = service.build(
            dependencies=[sample_dependency],
            findings=[vuln1, vuln2, vuln3],
        )

        assert result.provider_count == {"OSV": 2, "GHSA": 2, "NVD": 2}

    def test_build_dependency_occurrence_count(
        self, service, sample_dependency
    ):
        """Test du comptage des occurrences par dépendance."""
        vuln1 = Mock(spec=VulnerabilityInfo)
        vuln1.dependency_name = "requests"
        vuln1.identifier = "CVE-001"
        vuln1.sources = [Provider.OSV]

        vuln2 = Mock(spec=VulnerabilityInfo)
        vuln2.dependency_name = "requests"
        vuln2.identifier = "CVE-002"
        vuln2.sources = [Provider.OSV]

        vuln3 = Mock(spec=VulnerabilityInfo)
        vuln3.dependency_name = "requests"
        vuln3.identifier = "CVE-003"
        vuln3.sources = [Provider.OSV]

        vuln4 = Mock(spec=VulnerabilityInfo)
        vuln4.dependency_name = "flask"
        vuln4.identifier = "CVE-004"
        vuln4.sources = [Provider.OSV]

        result = service.build(
            dependencies=[sample_dependency],
            findings=[vuln1, vuln2, vuln3, vuln4],
        )

        assert result.dependency_occurrence_count == {
            "requests": 3,
            "flask": 1,
        }

    def test_build_with_many_dependencies(self, service):
        """Test avec un grand nombre de dépendances."""
        dependencies = []
        for i in range(100):
            dep = Mock(spec=ScannedDependency)
            dep.name = f"package-{i}"
            dep.version = "1.0.0"
            dep.ecosystem = "pypi"
            dependencies.append(dep)

        result = service.build(
            dependencies=dependencies,
            findings=[],
        )

        assert result.dependency_count == 100
        assert result.occurrence_count == 0


class TestFindingStatisticsServiceEdgeCases:
    """Tests des cas limites."""

    def test_build_with_vulnerability_no_sources(
        self, service, sample_dependency
    ):
        """Test avec un finding sans sources."""
        vuln = Mock(spec=VulnerabilityInfo)
        vuln.dependency_name = "requests"
        vuln.identifier = "CVE-001"
        vuln.sources = []

        result = service.build(
            dependencies=[sample_dependency],
            findings=[vuln],
        )

        assert result.provider_count == {}
        assert result.occurrence_count == 1
        assert result.unique_vulnerability_count == 1

    def test_build_with_all_duplicated_identifiers(
        self, service, sample_dependency
    ):
        """Test où tous les identifiers sont dupliqués."""
        vuln1 = Mock(spec=VulnerabilityInfo)
        vuln1.dependency_name = "requests"
        vuln1.identifier = "CVE-SAME"
        vuln1.sources = [Provider.OSV]

        vuln2 = Mock(spec=VulnerabilityInfo)
        vuln2.dependency_name = "flask"
        vuln2.identifier = "CVE-SAME"
        vuln2.sources = [Provider.GHSA]

        vuln3 = Mock(spec=VulnerabilityInfo)
        vuln3.dependency_name = "django"
        vuln3.identifier = "CVE-SAME"
        vuln3.sources = [Provider.NVD]

        result = service.build(
            dependencies=[sample_dependency],
            findings=[vuln1, vuln2, vuln3],
        )

        assert result.occurrence_count == 3
        assert result.unique_vulnerability_count == 1
        assert (
            result.duplicated_identifier_count == 1
        )  # Un seul identifier, mais dupliqué

    def test_build_dependency_count_independent_of_findings(
        self, service, sample_dependency
    ):
        """Test que dependency_count dépend uniquement des dependencies, pas des findings."""
        dep2 = Mock(spec=ScannedDependency)
        dep2.name = "flask"
        dep2.version = "2.0.0"
        dep2.ecosystem = "pypi"

        # 2 dependencies, 0 findings
        result1 = service.build(
            dependencies=[sample_dependency, dep2],
            findings=[],
        )
        assert result1.dependency_count == 2

        # 2 dependencies, 10 findings
        findings = []
        for i in range(10):
            vuln = Mock(spec=VulnerabilityInfo)
            vuln.dependency_name = "requests"
            vuln.identifier = f"CVE-{i}"
            vuln.sources = [Provider.OSV]
            findings.append(vuln)

        result2 = service.build(
            dependencies=[sample_dependency, dep2],
            findings=findings,
        )
        assert result2.dependency_count == 2  # Toujours 2

    def test_build_occurrence_count_equals_findings_length(
        self, service, sample_dependency
    ):
        """Test que occurrence_count == len(findings)."""
        findings = []
        for i in range(50):
            vuln = Mock(spec=VulnerabilityInfo)
            vuln.dependency_name = f"pkg-{i % 5}"
            vuln.identifier = f"CVE-{i}"
            vuln.sources = [Provider.OSV]
            findings.append(vuln)

        result = service.build(
            dependencies=[sample_dependency],
            findings=findings,
        )

        assert result.occurrence_count == 50


class TestFindingStatisticsServiceIdentifierCounting:
    """Tests spécifiques au comptage des identifiers."""

    def test_unique_vs_duplicated_identifiers(
        self, service, sample_dependency
    ):
        """Test de la logique unique vs duplicated."""
        # 3 identifiers uniques, 2 identifiers dupliqués
        vulns = []

        # Identifier unique 1
        vuln = Mock(spec=VulnerabilityInfo)
        vuln.dependency_name = "pkg1"
        vuln.identifier = "UNIQUE-1"
        vuln.sources = [Provider.OSV]
        vulns.append(vuln)

        # Identifier unique 2
        vuln = Mock(spec=VulnerabilityInfo)
        vuln.dependency_name = "pkg2"
        vuln.identifier = "UNIQUE-2"
        vuln.sources = [Provider.OSV]
        vulns.append(vuln)

        # Identifier unique 3
        vuln = Mock(spec=VulnerabilityInfo)
        vuln.dependency_name = "pkg3"
        vuln.identifier = "UNIQUE-3"
        vuln.sources = [Provider.OSV]
        vulns.append(vuln)

        # Identifier dupliqué 1 (apparaît 2 fois)
        for _ in range(2):
            vuln = Mock(spec=VulnerabilityInfo)
            vuln.dependency_name = "pkg4"
            vuln.identifier = "DUP-1"
            vuln.sources = [Provider.OSV]
            vulns.append(vuln)

        # Identifier dupliqué 2 (apparaît 3 fois)
        for _ in range(3):
            vuln = Mock(spec=VulnerabilityInfo)
            vuln.dependency_name = "pkg5"
            vuln.identifier = "DUP-2"
            vuln.sources = [Provider.OSV]
            vulns.append(vuln)

        result = service.build(
            dependencies=[sample_dependency],
            findings=vulns,
        )

        # Total: 1 + 1 + 1 + 2 + 3 = 8 findings
        assert result.occurrence_count == 8

        # Identifiers uniques: UNIQUE-1, UNIQUE-2, UNIQUE-3, DUP-1, DUP-2 = 5
        assert result.unique_vulnerability_count == 5
        assert result.unique_identifier_count == 5

        # Identifiers dupliqués: DUP-1 (count=2), DUP-2 (count=3) = 2
        assert result.duplicated_identifier_count == 2

    def test_identifier_appears_exactly_twice(
        self, service, sample_dependency
    ):
        """Test avec un identifier apparaissant exactement 2 fois."""
        vuln1 = Mock(spec=VulnerabilityInfo)
        vuln1.dependency_name = "pkg1"
        vuln1.identifier = "CVE-DOUBLE"
        vuln1.sources = [Provider.OSV]

        vuln2 = Mock(spec=VulnerabilityInfo)
        vuln2.dependency_name = "pkg2"
        vuln2.identifier = "CVE-DOUBLE"
        vuln2.sources = [Provider.GHSA]

        result = service.build(
            dependencies=[sample_dependency],
            findings=[vuln1, vuln2],
        )

        assert result.duplicated_identifier_count == 1
        assert result.unique_vulnerability_count == 1


class TestFindingStatisticsServiceProviderCounting:
    """Tests spécifiques au comptage des providers."""

    def test_provider_count_with_single_provider_per_finding(
        self, service, sample_dependency
    ):
        """Test avec un seul provider par finding."""
        vuln1 = Mock(spec=VulnerabilityInfo)
        vuln1.dependency_name = "pkg1"
        vuln1.identifier = "CVE-001"
        vuln1.sources = [Provider.OSV]

        vuln2 = Mock(spec=VulnerabilityInfo)
        vuln2.dependency_name = "pkg2"
        vuln2.identifier = "CVE-002"
        vuln2.sources = [Provider.GHSA]

        vuln3 = Mock(spec=VulnerabilityInfo)
        vuln3.dependency_name = "pkg3"
        vuln3.identifier = "CVE-003"
        vuln3.sources = [Provider.NVD]

        result = service.build(
            dependencies=[sample_dependency],
            findings=[vuln1, vuln2, vuln3],
        )

        assert result.provider_count == {"OSV": 1, "GHSA": 1, "NVD": 1}

    def test_provider_count_with_multiple_providers_per_finding(
        self, service, sample_dependency
    ):
        """Test avec plusieurs providers par finding."""
        vuln1 = Mock(spec=VulnerabilityInfo)
        vuln1.dependency_name = "pkg1"
        vuln1.identifier = "CVE-001"
        vuln1.sources = [Provider.OSV, Provider.GHSA, Provider.NVD]

        result = service.build(
            dependencies=[sample_dependency],
            findings=[vuln1],
        )

        assert result.provider_count == {"OSV": 1, "GHSA": 1, "NVD": 1}

    def test_provider_count_accumulation(self, service, sample_dependency):
        """Test que les counts de providers s'accumulent correctement."""
        vuln1 = Mock(spec=VulnerabilityInfo)
        vuln1.dependency_name = "pkg1"
        vuln1.identifier = "CVE-001"
        vuln1.sources = [Provider.OSV, Provider.GHSA]

        vuln2 = Mock(spec=VulnerabilityInfo)
        vuln2.dependency_name = "pkg2"
        vuln2.identifier = "CVE-002"
        vuln2.sources = [Provider.OSV]

        vuln3 = Mock(spec=VulnerabilityInfo)
        vuln3.dependency_name = "pkg3"
        vuln3.identifier = "CVE-003"
        vuln3.sources = [Provider.OSV, Provider.GHSA, Provider.NVD]

        result = service.build(
            dependencies=[sample_dependency],
            findings=[vuln1, vuln2, vuln3],
        )

        # OSV: 3 fois (vuln1, vuln2, vuln3)
        # GHSA: 2 fois (vuln1, vuln3)
        # NVD: 1 fois (vuln3)
        assert result.provider_count == {"OSV": 3, "GHSA": 2, "NVD": 1}
