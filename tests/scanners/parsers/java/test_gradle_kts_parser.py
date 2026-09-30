from pathlib import Path

import pytest

from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.java.parsers.gradle_kts_parser import GradleKtsParser


@pytest.fixture
def parser() -> GradleKtsParser:
    return GradleKtsParser()


def create_gradle_file(
    project_path: Path,
    content: str,
) -> Path:
    file = project_path / "build.gradle.kts"
    file.write_text(content, encoding="utf-8")
    return file


def create_version_catalog(
    project_path: Path,
    content: str,
) -> Path:
    gradle_directory = project_path / "gradle"
    gradle_directory.mkdir(exist_ok=True)

    file = gradle_directory / "libs.versions.toml"
    file.write_text(content, encoding="utf-8")

    return file


def test_supports_returns_true_when_build_gradle_kts_exists(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        plugins {
            id("java")
        }
        """,
    )

    assert parser.supports(tmp_path) is True


def test_supports_returns_false_when_build_gradle_kts_does_not_exist(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    assert parser.supports(tmp_path) is False


def test_parse_returns_empty_list_when_file_does_not_exist(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    assert parser.parse(tmp_path) == []


def test_parse_implementation_dependency(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation("org.springframework:spring-core:6.2.0")
        }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "org.springframework:spring-core"
    assert dependency.version == "6.2.0"
    assert dependency.ecosystem == Ecosystem.MAVEN.value
    assert dependency.source == "build.gradle.kts"
    assert dependency.priority == DependencySourcePriority.MANIFEST


@pytest.mark.parametrize(
    "configuration",
    [
        "implementation",
        "api",
        "compileOnly",
        "runtimeOnly",
        "testImplementation",
        "testCompileOnly",
        "testRuntimeOnly",
        "annotationProcessor",
    ],
)
def test_parse_supported_configurations(
    parser: GradleKtsParser,
    tmp_path: Path,
    configuration: str,
) -> None:
    create_gradle_file(
        tmp_path,
        f"""
        dependencies {{
            {configuration}("org.example:library:1.2.3")
        }}
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "org.example:library"
    assert dependency.version == "1.2.3"
    assert dependency.ecosystem == Ecosystem.MAVEN.value
    assert dependency.source == "build.gradle.kts"
    assert dependency.priority == DependencySourcePriority.MANIFEST


def test_parse_multiple_dependencies(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        plugins {
            id("java")
        }

        dependencies {
            implementation("org.springframework:spring-core:6.2.0")
            api("com.fasterxml.jackson.core:jackson-databind:2.18.2")
            compileOnly("org.projectlombok:lombok:1.18.36")
            runtimeOnly("org.postgresql:postgresql:42.7.4")
            testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
        }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 5

    assert dependencies[0].name == "org.springframework:spring-core"
    assert dependencies[0].version == "6.2.0"

    assert (
        dependencies[1].name == "com.fasterxml.jackson.core:jackson-databind"
    )
    assert dependencies[1].version == "2.18.2"

    assert dependencies[2].name == "org.projectlombok:lombok"
    assert dependencies[2].version == "1.18.36"

    assert dependencies[3].name == "org.postgresql:postgresql"
    assert dependencies[3].version == "42.7.4"

    assert dependencies[4].name == "org.junit.jupiter:junit-jupiter"
    assert dependencies[4].version == "5.11.3"


def test_parse_single_quoted_dependency(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation('org.example:library:1.2.3')
        }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    assert dependencies[0].name == "org.example:library"
    assert dependencies[0].version == "1.2.3"


def test_parse_dependency_with_spaces(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation(
                "org.example:library:1.2.3"
            )
        }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    assert dependencies[0].name == "org.example:library"
    assert dependencies[0].version == "1.2.3"


def test_parse_ignores_dependency_without_version(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation("org.example:library")
        }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_project_dependency(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation(project(":common"))
        }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_version_catalog_dependency(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation(libs.spring.core)
        }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_platform_dependency(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation(
                platform("org.springframework.boot:spring-boot-dependencies:3.4.1")
            )
        }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_unsupported_configuration(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            customConfiguration("org.example:library:1.2.3")
        }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_non_dependency_content(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        plugins {
            id("org.springframework.boot") version "3.4.1"
        }

        repositories {
            mavenCentral()
        }

        group = "org.example"
        version = "1.0.0"

        tasks {
            register("hello")
        }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_dependency_with_hyphen_and_underscore(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation(
                "org.example:my-library_name:1.2.3"
            )
        }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    assert dependencies[0].name == "org.example:my-library_name"
    assert dependencies[0].version == "1.2.3"


def test_parse_multiple_dependency_blocks(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation("org.example:first:1.0.0")
        }

        dependencies {
            testImplementation("org.example:second:2.0.0")
        }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 2

    assert dependencies[0].name == "org.example:first"
    assert dependencies[0].version == "1.0.0"

    assert dependencies[1].name == "org.example:second"
    assert dependencies[1].version == "2.0.0"


def test_parse_utf8_content(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        // Projet dépendant d'un composant externe
        dependencies {
            implementation("org.example:library:1.2.3")
        }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "org.example:library"
    assert dependencies[0].version == "1.2.3"


def test_parse_version_catalog_dependency(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation(libs.spring.core)
        }
        """,
    )

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
    assert dependency.ecosystem == Ecosystem.MAVEN.value
    assert dependency.source == "build.gradle.kts"
    assert dependency.priority == DependencySourcePriority.MANIFEST


def test_parse_multiple_version_catalog_dependencies(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation(libs.spring.core)
            implementation(libs.jackson.databind)
            testImplementation(libs.junit.jupiter)
        }
        """,
    )

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


def test_parse_ignores_unknown_version_catalog_alias(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation(libs.unknown.library)
        }
        """,
    )

    create_version_catalog(
        tmp_path,
        """
        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = "6.2.0" }
        """,
    )

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_mixed_standard_and_version_catalog_dependencies(
    parser: GradleKtsParser,
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation("org.example:library:1.0.0")
            implementation(libs.spring.core)
        }
        """,
    )

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

    assert len(dependencies) == 2

    assert dependencies[0].name == "org.example:library"
    assert dependencies[0].version == "1.0.0"

    assert dependencies[1].name == "org.springframework:spring-core"
    assert dependencies[1].version == "6.2.0"
