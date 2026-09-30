from pathlib import Path

from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.java.parsers.pom_parser import PomParser


def test_supports(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "pom.xml",
        "<project/>",
    )

    parser = PomParser()

    assert parser.supports(temp_project)


def test_not_supports(
    temp_project: Path,
) -> None:
    parser = PomParser()

    assert not parser.supports(temp_project)


def test_parse_empty(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "pom.xml",
        """
<project>
</project>
""",
    )

    parser = PomParser()

    deps = parser.parse(temp_project)

    assert deps == []


def test_parse_single_dependency(
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

    parser = PomParser()

    deps = parser.parse(temp_project)

    assert len(deps) == 1

    dep = deps[0]

    assert dep.name == "org.springframework:spring-core"
    assert dep.version == "6.2.1"
    assert dep.ecosystem == Ecosystem.MAVEN.value
    assert dep.source == "pom.xml"


def test_parse_multiple_dependencies(
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

        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <version>2.0.17</version>
        </dependency>
    </dependencies>
</project>
""",
    )

    parser = PomParser()

    deps = parser.parse(temp_project)

    assert len(deps) == 2

    names = {dep.name for dep in deps}

    assert names == {
        "org.springframework:spring-core",
        "org.slf4j:slf4j-api",
    }


def test_ignore_invalid_dependency(
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

        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
        </dependency>

    </dependencies>
</project>
""",
    )

    parser = PomParser()

    deps = parser.parse(temp_project)

    assert len(deps) == 1
    assert deps[0].name == "org.springframework:spring-core"


def test_missing_version(
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
        </dependency>

    </dependencies>
</project>
""",
    )

    parser = PomParser()

    deps = parser.parse(temp_project)

    assert deps == []
