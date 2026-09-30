import json

from sentinel.dto.scan_result import ScanResult
from sentinel.renderers.base import BaseRenderer


class SarifRenderer(BaseRenderer):
    def render(
        self,
        result: ScanResult,
    ) -> str:

        results: list[dict[str, object]] = []

        rules: list[dict[str, object]] = []

        for finding in result.findings:
            rules.append(
                {
                    "id": finding.identifier,
                    "name": finding.identifier,
                    "shortDescription": {
                        "text": finding.summary,
                    },
                }
            )

            results.append(
                {
                    "ruleId": finding.identifier,
                    "level": self._severity_level(
                        finding.severity.value,
                    ),
                    "message": {
                        "text": finding.summary,
                    },
                    "properties": {
                        "dependency": finding.dependency_name,
                        "version": finding.dependency_version,
                        "cvss": finding.cvss,
                        "sources": [
                            source.value for source in finding.sources
                        ],
                        "known_exploited": (finding.known_exploited),
                        "epss_score": finding.epss_score,
                        "vulncheck_known_exploited": (
                            finding.vulncheck_known_exploited
                        ),
                        "vulncheck_date_added": (
                            finding.vulncheck_date_added.isoformat()
                            if finding.vulncheck_date_added is not None
                            else None
                        ),
                        "vulncheck_cisa_date_added": (
                            finding.vulncheck_cisa_date_added.isoformat()
                            if finding.vulncheck_cisa_date_added is not None
                            else None
                        ),
                        "vulncheck_due_date": (
                            finding.vulncheck_due_date.isoformat()
                            if finding.vulncheck_due_date is not None
                            else None
                        ),
                        "vulncheck_vendor": (finding.vulncheck_vendor),
                        "vulncheck_product": (finding.vulncheck_product),
                        "vulncheck_required_action": (
                            finding.vulncheck_required_action
                        ),
                        "vulncheck_known_ransomware": (
                            finding.vulncheck_known_ransomware
                        ),
                        "vulncheck_reported_exploited_by_canaries": (
                            finding.vulncheck_reported_exploited_by_canaries
                        ),
                    },
                }
            )

        sarif = {
            "version": "2.1.0",
            "$schema": ("https://json.schemastore.org/sarif-2.1.0.json"),
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Sentinel",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(
            sarif,
            indent=2,
        )

    @staticmethod
    def _severity_level(
        severity: str,
    ) -> str:

        match severity.upper():
            case "CRITICAL" | "HIGH":
                return "error"

            case "MEDIUM":
                return "warning"

            case "LOW":
                return "note"

            case _:
                return "none"
