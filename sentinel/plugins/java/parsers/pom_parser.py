from __future__ import annotations

from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.parsers.base_xml_parser import BaseXmlParser


class PomParser(BaseXmlParser):
    """
    Parser for Maven pom.xml files.
    """

    FILE = "pom.xml"

    PRIORITY = DependencySourcePriority.MANIFEST

    def parse(
        self,
        project_path: Path,
    ) -> list[ScannedDependency]:
        root = self.load(project_path)

        dependencies: list[ScannedDependency] = []

        for dependency in self.find_all(
            root,
            "./dependencies/dependency",
        ):
            group_id = self.find_text(
                dependency,
                "groupId",
            )
            artifact_id = self.find_text(
                dependency,
                "artifactId",
            )
            version = self.find_text(
                dependency,
                "version",
            )

            if group_id is None or artifact_id is None or version is None:
                continue

            dependencies.append(
                ScannedDependency(
                    name=f"{group_id}:{artifact_id}",
                    version=version,
                    ecosystem=Ecosystem.MAVEN,
                    source=self.FILE,
                    priority=self.PRIORITY,
                )
            )

        return dependencies
