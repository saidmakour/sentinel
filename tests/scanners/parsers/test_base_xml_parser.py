from pathlib import Path

import pytest

from sentinel.scanners.parsers.base_xml_parser import BaseXmlParser


class DummyXmlParser(BaseXmlParser):
    FILE = "test.xml"

    def supports(
        self,
        project_path: Path,
    ) -> bool:
        return (project_path / self.FILE).exists()

    def parse(self, project_path: Path):
        return []


def test_supports(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "test.xml",
        "<root/>",
    )

    parser = DummyXmlParser()

    assert parser.supports(temp_project)


def test_not_supports(
    temp_project: Path,
) -> None:
    parser = DummyXmlParser()

    assert not parser.supports(temp_project)


def test_load(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "test.xml",
        """
<root>
    <name>Sentinel</name>
</root>
""",
    )

    parser = DummyXmlParser()

    root = parser.load(temp_project)

    assert root.tag == "root"


def test_find_text(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "test.xml",
        """
<root>
    <name>Sentinel</name>
</root>
""",
    )

    parser = DummyXmlParser()

    root = parser.load(temp_project)

    assert parser.find_text(root, "name") == "Sentinel"


def test_find_text_missing(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "test.xml",
        "<root/>",
    )

    parser = DummyXmlParser()

    root = parser.load(temp_project)

    assert parser.find_text(root, "name") is None


def test_find_all(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "test.xml",
        """
<root>
    <item>A</item>
    <item>B</item>
    <item>C</item>
</root>
""",
    )

    parser = DummyXmlParser()

    root = parser.load(temp_project)

    items = parser.find_all(root, "item")

    assert len(items) == 3
    assert items[0].text == "A"
    assert items[1].text == "B"
    assert items[2].text == "C"


def test_invalid_xml(
    temp_project: Path,
    create_file,
) -> None:
    create_file(
        temp_project,
        "test.xml",
        "<root>",
    )

    parser = DummyXmlParser()

    with pytest.raises(ValueError):
        parser.load(temp_project)


def test_load_removes_namespaces(
    temp_project: Path,
    create_file,
) -> None:

    create_file(
        temp_project,
        "test.xml",
        """
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <artifactId>spring-core</artifactId>
        </dependency>
    </dependencies>
</project>
""",
    )

    parser = DummyXmlParser()
    root = parser.load(temp_project)

    deps = parser.find_all(
        root,
        "./dependencies/dependency",
    )

    assert len(deps) == 1
    assert (
        parser.find_text(
            deps[0],
            "artifactId",
        )
        == "spring-core"
    )
