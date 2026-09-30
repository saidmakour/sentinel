from pathlib import Path

from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.java.parsers.gradle_parser import GradleParser


def create_gradle_file(
    project_path: Path,
    content: str,
) -> Path:
    file = project_path / "build.gradle"

    file.write_text(
        content,
        encoding="utf-8",
    )

    return file


def test_supports_build_gradle(
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        "",
    )

    parser = GradleParser()

    assert parser.supports(tmp_path)


def test_does_not_support_missing_build_gradle(
    tmp_path: Path,
) -> None:
    parser = GradleParser()

    assert not parser.supports(tmp_path)


def test_parse_implementation_dependency(
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation 'org.springframework:spring-core:6.2.0'
        }
        """,
    )

    parser = GradleParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "org.springframework:spring-core"
    assert dependency.version == "6.2.0"
    assert dependency.ecosystem == Ecosystem.MAVEN.value
    assert dependency.source == "build.gradle"
    assert dependency.priority == (DependencySourcePriority.MANIFEST)


def test_parse_multiple_dependencies(
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation 'org.springframework:spring-core:6.2.0'
            api "com.google.guava:guava:33.3.1-jre"
            compileOnly 'org.projectlombok:lombok:1.18.36'
            runtimeOnly 'com.h2database:h2:2.3.232'
            testImplementation 'org.junit.jupiter:junit-jupiter:5.11.3'
            testRuntimeOnly 'org.junit.platform:junit-platform-launcher:1.11.3'
        }
        """,
    )

    parser = GradleParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 6

    dependencies_by_name = {
        dependency.name: dependency for dependency in dependencies
    }

    assert (
        dependencies_by_name["org.springframework:spring-core"].version
        == "6.2.0"
    )

    assert (
        dependencies_by_name["com.google.guava:guava"].version == "33.3.1-jre"
    )

    assert (
        dependencies_by_name["org.projectlombok:lombok"].version == "1.18.36"
    )

    assert dependencies_by_name["com.h2database:h2"].version == "2.3.232"

    assert (
        dependencies_by_name["org.junit.jupiter:junit-jupiter"].version
        == "5.11.3"
    )

    assert (
        dependencies_by_name[
            "org.junit.platform:junit-platform-launcher"
        ].version
        == "1.11.3"
    )


def test_parse_parenthesized_dependency(
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation('org.springframework:spring-core:6.2.0')
        }
        """,
    )

    parser = GradleParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == ("org.springframework:spring-core")
    assert dependency.version == "6.2.0"
    assert dependency.ecosystem == Ecosystem.MAVEN.value


def test_parse_ignores_invalid_dependency(
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        dependencies {
            implementation 'org.springframework:spring-core'
            implementation 'invalid'
            implementation 'org.springframework:spring-core:6.2.0:extra'
        }
        """,
    )

    parser = GradleParser()

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_parse_ignores_unrelated_lines(
    tmp_path: Path,
) -> None:
    create_gradle_file(
        tmp_path,
        """
        plugins {
            id 'java'
        }

        repositories {
            mavenCentral()
        }

        dependencies {
            implementation 'org.springframework:spring-core:6.2.0'
        }
        """,
    )

    parser = GradleParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    assert dependencies[0].name == ("org.springframework:spring-core")
