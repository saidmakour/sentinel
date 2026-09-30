from pathlib import Path
from unittest.mock import MagicMock

from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.java.parsers.gradle_kts_parser import GradleKtsParser
from sentinel.plugins.java.parsers.gradle_parser import GradleParser
from sentinel.plugins.java.parsers.pom_parser import PomParser
from sentinel.plugins.java.scanner import JavaScanner
from sentinel.scanners.parsers.base_parser import BaseParser


def test_scan_pom_file(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "pom.xml",
        """
<project>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>6.2.1</version>
        </dependency>
    </dependencies>
</project>
""",
    )

    scanner = JavaScanner()

    deps = scanner.scan(temp_project)

    assert len(deps) == 1

    dep = deps[0]

    assert dep.name == "org.springframework:spring-core"
    assert dep.version == "6.2.1"
    assert dep.ecosystem == Ecosystem.MAVEN.value


def test_scan_empty_project(
    temp_project: Path,
) -> None:
    scanner = JavaScanner()

    deps = scanner.scan(temp_project)

    assert deps == []


def test_dependencies_are_sorted(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "pom.xml",
        """
<project>
    <dependencies>

        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <version>2.0.17</version>
        </dependency>

        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>6.2.1</version>
        </dependency>

    </dependencies>
</project>
""",
    )

    scanner = JavaScanner()

    deps = scanner.scan(temp_project)

    assert len(deps) == 2

    assert deps[0].name == "org.slf4j:slf4j-api"
    assert deps[1].name == "org.springframework:spring-core"


def test_java_scanner_contains_gradle_parser() -> None:
    scanner = JavaScanner()

    assert any(isinstance(parser, GradleParser) for parser in scanner.parsers)


def test_java_scanner_contains_gradle_kts_parser() -> None:
    scanner = JavaScanner()

    assert any(
        isinstance(parser, GradleKtsParser) for parser in scanner.parsers
    )


def test_java_scanner_contains_pom_parser() -> None:
    scanner = JavaScanner()

    assert any(isinstance(parser, PomParser) for parser in scanner.parsers)


def test_java_scanner_has_two_parsers() -> None:
    scanner = JavaScanner()

    assert len(scanner.parsers) == 3


def create_project_files(
    project_path: Path,
) -> None:
    pom_file = project_path / "pom.xml"
    pom_file.write_text(
        """
        <project>
            <modelVersion>4.0.0</modelVersion>

            <groupId>org.example</groupId>
            <artifactId>example-project</artifactId>
            <version>1.0.0</version>

            <dependencies>
                <dependency>
                    <groupId>org.apache.commons</groupId>
                    <artifactId>commons-lang3</artifactId>
                    <version>3.17.0</version>
                </dependency>
            </dependencies>
        </project>
        """,
        encoding="utf-8",
    )

    gradle_file = project_path / "build.gradle.kts"
    gradle_file.write_text(
        """
        dependencies {
            implementation("com.google.guava:guava:33.3.1-jre")
            implementation(libs.spring.core)
        }
        """,
        encoding="utf-8",
    )

    gradle_directory = project_path / "gradle"
    gradle_directory.mkdir()

    version_catalog = gradle_directory / "libs.versions.toml"
    version_catalog.write_text(
        """
        [versions]

        spring = "6.2.0"

        [libraries]

        spring-core = { module = "org.springframework:spring-core", version = { ref = "spring" } }
        """,
        encoding="utf-8",
    )


def test_java_scanner_parses_maven_and_gradle_dependencies(
    tmp_path: Path,
) -> None:
    create_project_files(tmp_path)

    scanner = JavaScanner()

    dependencies = scanner.scan(tmp_path)

    dependencies_by_name = {
        dependency.name: dependency for dependency in dependencies
    }

    assert dependencies_by_name.keys() == {
        "org.apache.commons:commons-lang3",
        "com.google.guava:guava",
        "org.springframework:spring-core",
    }

    assert (
        dependencies_by_name["org.apache.commons:commons-lang3"].version
        == "3.17.0"
    )

    assert (
        dependencies_by_name["com.google.guava:guava"].version == "33.3.1-jre"
    )

    assert (
        dependencies_by_name["org.springframework:spring-core"].version
        == "6.2.0"
    )

    assert all(
        dependency.ecosystem == Ecosystem.MAVEN.value
        for dependency in dependencies
    )


def test_java_scanner_accepts_custom_parsers() -> None:
    parser = MagicMock(spec=BaseParser)

    scanner = JavaScanner(parsers=[parser])

    assert scanner.parsers == [parser]


def test_node_scanner_uses_default_parsers() -> None:
    scanner = JavaScanner()

    assert len(scanner.parsers) == 3
