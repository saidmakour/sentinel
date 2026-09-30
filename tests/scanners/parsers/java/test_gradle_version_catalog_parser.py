from pathlib import Path

import pytest

from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.java.parsers.gradle_version_catalog_parser import (
    GradleVersionCatalogParser,
)


@pytest.fixture
def parser() -> GradleVersionCatalogParser:
    return GradleVersionCatalogParser()


def create_version_catalog(
    project_path: Path,
    content: str,
) -> Path:
    gradle_directory = project_path / "gradle"
    gradle_directory.mkdir()

    file = gradle_directory / "libs.versions.toml"
    file.write_text(content, encoding="utf-8")

    return file


def test_supports_returns_true_when_version_catalog_exists(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [versions]

        spring = "6.2.0"
        """,
    )

    assert parser.supports(tmp_path) is True


def test_supports_returns_false_when_version_catalog_does_not_exist(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    assert parser.supports(tmp_path) is False


def test_parse_module_with_explicit_version(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = "6.2.0" }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "org.springframework:spring-core"
    assert dependency.version == "6.2.0"
    assert dependency.ecosystem == Ecosystem.MAVEN.value
    assert dependency.source == "gradle/libs.versions.toml"
    assert dependency.priority == DependencySourcePriority.MANIFEST


def test_parse_module_with_version_ref(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [versions]

        spring = "6.2.0"

        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = { ref = "spring" } }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "org.springframework:spring-core"
    assert dependency.version == "6.2.0"


def test_parse_group_and_name_with_explicit_version(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { group = "org.springframework", name = "spring-core", version = "6.2.0" }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "org.springframework:spring-core"
    assert dependency.version == "6.2.0"


def test_parse_group_and_name_with_version_ref(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [versions]

        spring = "6.2.0"

        [libraries]

        spring-core = { group = "org.springframework", name = "spring-core", version = { ref = "spring" } }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "org.springframework:spring-core"
    assert dependency.version == "6.2.0"


def test_parse_multiple_libraries(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [versions]

        spring = "6.2.0"
        jackson = "2.18.2"
        junit = "5.11.3"

        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = { ref = "spring" } }
        jackson-databind = { module = "com.fasterxml.jackson.core:jackson-databind", version = { ref = "jackson" } }
        junit-jupiter = { module = "org.junit.jupiter:junit-jupiter", version = { ref = "junit" } }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 3

    assert dependencies[0].name == "org.springframework:spring-core"
    assert dependencies[0].version == "6.2.0"

    assert dependencies[1].name == (
        "com.fasterxml.jackson.core:jackson-databind"
    )
    assert dependencies[1].version == "2.18.2"

    assert dependencies[2].name == "org.junit.jupiter:junit-jupiter"
    assert dependencies[2].version == "5.11.3"


def test_parse_ignores_library_without_module_or_group_and_name(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        invalid-library = { version = "1.2.3" }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_library_with_group_only(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        invalid-library = { group = "org.example", version = "1.2.3" }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_library_with_name_only(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        invalid-library = { name = "library", version = "1.2.3" }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_library_without_version(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "org.springframework:spring-core" }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_library_with_unknown_version_ref(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = { ref = "unknown" } }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_library_with_empty_module(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "", version = "6.2.0" }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_library_with_empty_group(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { group = "", name = "spring-core", version = "6.2.0" }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_library_with_empty_name(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { group = "org.springframework", name = "", version = "6.2.0" }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_library_with_empty_version(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = "" }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_library_with_empty_version_ref(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = { ref = "" } }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_non_dict_library_definition(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        invalid-library = "org.example:library:1.2.3"
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_unrelated_toml_sections(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [versions]

        spring = "6.2.0"

        [plugins]

        spring-boot = { id = "org.springframework.boot", version = { ref = "spring" } }

        [bundles]

        spring-stack = ["spring-core"]
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_prefers_module_over_group_and_name(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "org.springframework:spring-core", group = "org.invalid", name = "invalid", version = "6.2.0" }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    assert dependencies[0].name == "org.springframework:spring-core"
    assert dependencies[0].version == "6.2.0"


def test_parse_utf8_content(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        # Dépendance du projet

        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = "6.2.0" }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "org.springframework:spring-core"
    assert dependencies[0].version == "6.2.0"


def test_resolve_libs_alias(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [versions]

        spring = "6.2.0"

        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = { ref = "spring" } }
        """,
    )

    dependency = parser.resolve(
        "libs.spring.core",
        tmp_path,
    )

    assert dependency is not None
    assert dependency.name == "org.springframework:spring-core"
    assert dependency.version == "6.2.0"
    assert dependency.ecosystem == Ecosystem.MAVEN.value


def test_resolve_alias_without_libs_prefix(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = "6.2.0" }
        """,
    )

    dependency = parser.resolve(
        "spring.core",
        tmp_path,
    )

    assert dependency is not None
    assert dependency.name == "org.springframework:spring-core"
    assert dependency.version == "6.2.0"


def test_resolve_unknown_alias_returns_none(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = "6.2.0" }
        """,
    )

    dependency = parser.resolve(
        "libs.unknown.library",
        tmp_path,
    )

    assert dependency is None


def test_resolve_alias_with_multiple_levels(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        jackson-databind = { module = "com.fasterxml.jackson.core:jackson-databind", version = "2.18.2" }
        """,
    )

    dependency = parser.resolve(
        "libs.jackson.databind",
        tmp_path,
    )

    assert dependency is not None
    assert dependency.name == ("com.fasterxml.jackson.core:jackson-databind")
    assert dependency.version == "2.18.2"


def test_parse_library_with_strictly_version(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = { strictly = "6.2.0" } }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "org.springframework:spring-core"
    assert dependency.version == "6.2.0"


def test_parse_library_with_require_version(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = { require = "6.2.0" } }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "org.springframework:spring-core"
    assert dependency.version == "6.2.0"


def test_parse_library_with_prefer_version(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = { prefer = "6.2.0" } }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "org.springframework:spring-core"
    assert dependency.version == "6.2.0"


def test_parse_library_prefers_version_ref_over_constraints(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [versions]

        spring = "6.1.0"

        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = { ref = "spring", strictly = "6.2.0", require = "6.3.0", prefer = "6.4.0" } }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "org.springframework:spring-core"
    assert dependency.version == "6.1.0"


def test_parse_library_prefers_strictly_over_require_and_prefer(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = { strictly = "6.2.0", require = "6.3.0", prefer = "6.4.0" } }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "org.springframework:spring-core"
    assert dependency.version == "6.2.0"


def test_parse_library_ignores_empty_version_constraints(
    parser: GradleVersionCatalogParser,
    tmp_path: Path,
) -> None:
    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = { strictly = "", require = "", prefer = "" } }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []
