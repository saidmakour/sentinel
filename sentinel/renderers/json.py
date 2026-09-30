import json

from sentinel.dto.scan_result import ScanResult
from sentinel.renderers.base import BaseRenderer


class JsonRenderer(BaseRenderer):
    def render(
        self,
        result: ScanResult,
    ) -> str:
        return json.dumps(
            {
                "statistics": {
                    "dependency_count": (result.statistics.dependency_count),
                    "finding_count": (result.statistics.finding_count),
                    "severity": {
                        "critical": (result.statistics.severity.critical),
                        "high": (result.statistics.severity.high),
                        "medium": (result.statistics.severity.medium),
                        "low": (result.statistics.severity.low),
                        "unknown": (result.statistics.severity.unknown),
                    },
                },
                "findings": [finding.to_dict() for finding in result.findings],
            },
            indent=2,
        )
