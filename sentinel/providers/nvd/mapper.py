from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.log.logger import get_logger
from sentinel.providers.nvd.models import NVDResponse
from sentinel.providers.nvd.models import NVDVersionRange
from sentinel.providers.nvd.models import NVDVulnerability
from sentinel.utils.severity import severity_from_cvss

logger = get_logger(__name__)


class NVDMapper:
    def map(
        self,
        dependency: ScannedDependency,
        response: NVDResponse,
    ) -> list[VulnerabilityInfo]:

        logger.debug("ENTER NVDMapper.map")

        logger.debug(
            "NVDMapper input: dependency=%s version=%s ecosystem=%s "
            "vulnerabilities=%d",
            dependency.name,
            dependency.version,
            dependency.ecosystem,
            len(response.vulnerabilities),
        )

        results: list[VulnerabilityInfo] = []

        for vuln in response.vulnerabilities:
            logger.debug(
                "Mapping CVE id=%s dependency=%s",
                vuln.identifier,
                dependency.name,
            )

            matched_configurations = self._matching_configurations(
                dependency,
                vuln,
            )

            if not matched_configurations:
                continue

            for config in matched_configurations:
                logger.debug(
                    "NVD MATCHED CONFIG: CVE=%s "
                    "criteria=%r "
                    "vendor=%r "
                    "product=%r "
                    "start_including=%r "
                    "start_excluding=%r "
                    "end_including=%r "
                    "end_excluding=%r",
                    vuln.identifier,
                    config.criteria,
                    config.vendor,
                    config.product,
                    config.version_start_including,
                    config.version_start_excluding,
                    config.version_end_including,
                    config.version_end_excluding,
                )

            remediation = self._build_remediation(
                matched_configurations,
            )

            logger.debug(
                "NVD REMEDIATION: dependency=%s version=%s "
                "CVE=%s remediation=%s",
                dependency.name,
                dependency.version,
                vuln.identifier,
                remediation,
            )

            fixed_versions = [
                rule.fixed
                for rule in remediation.rules
                if rule.fixed is not None
            ]

            logger.debug(
                "NVD FIXED VERSIONS: dependency=%s version=%s "
                "CVE=%s fixed_versions=%s",
                dependency.name,
                dependency.version,
                vuln.identifier,
                fixed_versions,
            )

            results.append(
                VulnerabilityInfo(
                    identifier=vuln.identifier,
                    aliases=vuln.aliases,
                    dependency_name=dependency.name,
                    dependency_version=dependency.version,
                    ecosystem=dependency.ecosystem,
                    sources=[
                        Provider.NVD,
                    ],
                    severity=severity_from_cvss(
                        vuln.cvss,
                    ),
                    cvss=vuln.cvss,
                    summary=vuln.summary,
                    fixed_versions=list(
                        dict.fromkeys(
                            fixed_versions,
                        )
                    ),
                    remediation=remediation,
                )
            )

            logger.debug(
                "NVD MAPPER RETURN: id=%s dep=%s aliases=%s",
                vuln.identifier,
                dependency.name,
                vuln.aliases,
            )

        logger.debug(
            "NVDMapper output count=%d ids=%s",
            len(results),
            [item.identifier for item in results],
        )

        return results

    def _build_remediation(
        self,
        configurations: list[NVDVersionRange],
    ) -> RemediationInfo:
        rules: list[RemediationRule] = []

        for config in configurations:
            introduced = (
                config.version_start_including
                or config.version_start_excluding
            )

            fixed = (
                config.version_end_excluding or config.version_end_including
            )

            affected_range = self._build_affected_range(
                config,
            )

            if (
                introduced is None
                and fixed is None
                and affected_range is None
                and config.version is not None
            ):
                affected_range = f"=={config.version}"

            logger.debug(
                "NVD BUILD RULE: criteria=%r "
                "version=%r "
                "introduced=%r "
                "fixed=%r "
                "affected_range=%r",
                config.criteria,
                config.version,
                introduced,
                fixed,
                affected_range,
            )

            if introduced is None and fixed is None and affected_range is None:
                continue

            rules.append(
                RemediationRule(
                    introduced=introduced,
                    fixed=fixed,
                    affected_range=affected_range,
                )
            )

        return RemediationInfo(
            rules=rules,
        )

    @staticmethod
    def _build_affected_range(
        config: NVDVersionRange,
    ) -> str | None:
        parts: list[str] = []

        if config.version_start_including is not None:
            parts.append(
                f">={config.version_start_including}",
            )

        if config.version_start_excluding is not None:
            parts.append(
                f">{config.version_start_excluding}",
            )

        if config.version_end_including is not None:
            parts.append(
                f"<={config.version_end_including}",
            )

        if config.version_end_excluding is not None:
            parts.append(
                f"<{config.version_end_excluding}",
            )

        if not parts:
            return None

        return ",".join(parts)

    def _matching_configurations(
        self,
        dependency: ScannedDependency,
        vuln: NVDVulnerability,
    ) -> list[NVDVersionRange]:
        dependency_name = dependency.name.lower()

        matched: list[NVDVersionRange] = []

        for config in vuln.configurations:
            vendor = config.vendor.lower() if config.vendor else None
            product = config.product.lower() if config.product else None

            logger.info(
                "NVD CPE dependency=%s ecosystem=%s CVE=%s "
                "vendor=%s product=%s "
                "start_including=%s start_excluding=%s "
                "end_including=%s end_excluding=%s",
                dependency.name,
                dependency.ecosystem,
                vuln.identifier,
                vendor,
                product,
                config.version_start_including,
                config.version_start_excluding,
                config.version_end_including,
                config.version_end_excluding,
            )

            if product != dependency_name:
                continue
            target_software = config.target_software

            if not self._matches_ecosystem(
                dependency.ecosystem,
                vendor,
                target_software,
            ):
                logger.debug(
                    "NVD MATCH REJECTED: ecosystem mismatch "
                    "dependency=%s ecosystem=%s CVE=%s "
                    "vendor=%s product=%s",
                    dependency.name,
                    dependency.ecosystem,
                    vuln.identifier,
                    vendor,
                    product,
                )
                continue

            matched.append(config)

            logger.debug(
                "NVD MATCH REASON=CPE_PRODUCT_ECOSYSTEM "
                "dependency=%s ecosystem=%s CVE=%s "
                "vendor=%s product=%s",
                dependency.name,
                dependency.ecosystem,
                vuln.identifier,
                vendor,
                product,
            )

        if not matched:
            if not vuln.configurations:
                logger.debug(
                    "NVD NO CPE: dependency=%s CVE=%s",
                    dependency.name,
                    vuln.identifier,
                )

            logger.debug(
                "NVD MATCH REJECTED: dependency=%s version=%s "
                "ecosystem=%s CVE=%s",
                dependency.name,
                dependency.version,
                dependency.ecosystem,
                vuln.identifier,
            )
        else:
            logger.debug(
                "NVD MATCH ACCEPTED: dependency=%s version=%s "
                "ecosystem=%s CVE=%s matched_configurations=%d",
                dependency.name,
                dependency.version,
                dependency.ecosystem,
                vuln.identifier,
                len(matched),
            )

        return matched

    def _matches_ecosystem(
        self,
        ecosystem: Ecosystem,
        vendor: str | None,
        target_software: str | None,
    ) -> bool:
        if vendor is not None:
            vendor = vendor.lower()

        if target_software is not None:
            target_software = target_software.lower()

        if ecosystem is Ecosystem.PYPI:
            return vendor in {
                "python",
                "pypa",
            }

        if ecosystem is Ecosystem.NPM:
            return vendor in {
                "npmjs",
                "nodejs",
            } or target_software in {
                "node.js",
                "nodejs",
            }

        if ecosystem is Ecosystem.COMPOSER:
            return target_software in {
                "php",
                "composer",
            }

        if ecosystem is Ecosystem.MAVEN:
            return target_software in {
                "java",
                "maven",
            }

        if ecosystem is Ecosystem.GOLANG:
            return vendor == "golang" or target_software in {
                "go",
                "golang",
            }

        if ecosystem is Ecosystem.RUBYGEMS:
            return vendor == "ruby-lang" or target_software == "ruby"

        return False
