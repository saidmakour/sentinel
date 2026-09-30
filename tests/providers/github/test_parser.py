from sentinel.providers.github.parser import GitHubAdvisoryParser


def test_parse_complete_advisory() -> None:
    parser = GitHubAdvisoryParser()

    data = {
        "ghsa_id": "GHSA-abcd-1234-efgh",
        "cve_id": "CVE-2026-1234",
        "summary": "Test vulnerability",
        "description": "A test vulnerability.",
        "severity": "high",
        "identifiers": [
            {
                "type": "GHSA",
                "value": "GHSA-abcd-1234-efgh",
            },
            {
                "type": "CVE",
                "value": "CVE-2026-1234",
            },
        ],
        "vulnerabilities": [
            {
                "package": {
                    "ecosystem": "pip",
                    "name": "requests",
                },
                "vulnerable_version_range": "<2.32.0",
                "first_patched_version": "2.32.0",
                "vulnerable_functions": [
                    "foo",
                    "bar",
                ],
            },
        ],
        "cvss": {
            "score": 8.1,
            "vector_string": "CVSS:3.1/AV:N/AC:L",
        },
        "cvss_severities": {
            "cvss_v3": {
                "score": 8.1,
                "vector_string": "CVSS:3.1/AV:N/AC:L",
            },
            "cvss_v4": {
                "score": 8.5,
                "vector_string": "CVSS:4.0/AV:N/AC:L",
            },
        },
        "published_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
        "withdrawn_at": None,
        "references": [
            "https://example.com/advisory",
        ],
    }

    result = parser.parse(data)

    assert result is not None
    assert result.ghsa_id == "GHSA-abcd-1234-efgh"
    assert result.cve_id == "CVE-2026-1234"
    assert result.summary == "Test vulnerability"
    assert result.description == "A test vulnerability."
    assert result.severity == "high"

    assert len(result.identifiers) == 2
    assert result.identifiers[0].type == "GHSA"
    assert result.identifiers[0].value == "GHSA-abcd-1234-efgh"

    assert len(result.vulnerabilities) == 1

    vulnerability = result.vulnerabilities[0]

    assert vulnerability.package.ecosystem == "pip"
    assert vulnerability.package.name == "requests"
    assert vulnerability.vulnerable_version_range == "<2.32.0"
    assert vulnerability.first_patched_version == "2.32.0"
    assert vulnerability.vulnerable_functions == [
        "foo",
        "bar",
    ]

    assert result.cvss is not None
    assert result.cvss.score == 8.1
    assert result.cvss.vector_string == "CVSS:3.1/AV:N/AC:L"

    assert result.cvss_severities is not None
    assert result.cvss_severities.cvss_v3 is not None
    assert result.cvss_severities.cvss_v4 is not None
    assert result.cvss_severities.cvss_v3.score == 8.1
    assert result.cvss_severities.cvss_v4.score == 8.5

    assert result.published_at == "2026-01-01T00:00:00Z"
    assert result.updated_at == "2026-01-02T00:00:00Z"
    assert result.withdrawn_at is None
    assert result.references == [
        "https://example.com/advisory",
    ]


def test_parse_advisory_without_cve() -> None:
    parser = GitHubAdvisoryParser()

    data = {
        "ghsa_id": "GHSA-abcd-1234-efgh",
        "summary": "GHSA only vulnerability",
        "severity": "moderate",
        "cve_id": None,
    }

    result = parser.parse(data)

    assert result is not None
    assert result.ghsa_id == "GHSA-abcd-1234-efgh"
    assert result.cve_id is None
    assert result.summary == "GHSA only vulnerability"
    assert result.severity == "moderate"
    assert result.identifiers == []
    assert result.vulnerabilities == []


def test_parse_missing_ghsa_id_returns_none() -> None:
    parser = GitHubAdvisoryParser()

    result = parser.parse(
        {
            "summary": "Missing GHSA",
            "severity": "high",
        },
    )

    assert result is None


def test_parse_invalid_ghsa_id_returns_none() -> None:
    parser = GitHubAdvisoryParser()

    result = parser.parse(
        {
            "ghsa_id": 1234,
        },
    )

    assert result is None


def test_parse_defaults_missing_fields() -> None:
    parser = GitHubAdvisoryParser()

    result = parser.parse(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
        },
    )

    assert result is not None
    assert result.summary == ""
    assert result.description is None
    assert result.severity == "unknown"
    assert result.cve_id is None
    assert result.identifiers == []
    assert result.vulnerabilities == []
    assert result.cvss is None
    assert result.cvss_severities is None
    assert result.published_at is None
    assert result.updated_at is None
    assert result.withdrawn_at is None
    assert result.references == []


def test_parse_identifiers_ignores_invalid_items() -> None:
    parser = GitHubAdvisoryParser()

    result = parser.parse(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
            "identifiers": [
                {
                    "type": "GHSA",
                    "value": "GHSA-abcd-1234-efgh",
                },
                {
                    "type": "CVE",
                },
                {
                    "value": "CVE-2026-1234",
                },
                "invalid",
                None,
                123,
            ],
        },
    )

    assert result is not None
    assert len(result.identifiers) == 1
    assert result.identifiers[0].type == "GHSA"
    assert result.identifiers[0].value == "GHSA-abcd-1234-efgh"


def test_parse_vulnerabilities_ignores_invalid_items() -> None:
    parser = GitHubAdvisoryParser()

    result = parser.parse(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
            "vulnerabilities": [
                {
                    "package": {
                        "ecosystem": "pip",
                        "name": "requests",
                    },
                    "vulnerable_version_range": "<2.32.0",
                    "first_patched_version": "2.32.0",
                },
                {
                    "package": {
                        "ecosystem": "npm",
                    },
                },
                {
                    "package": {
                        "name": "requests",
                    },
                },
                {
                    "package": "invalid",
                },
                "invalid",
                None,
            ],
        },
    )

    assert result is not None
    assert len(result.vulnerabilities) == 1

    vulnerability = result.vulnerabilities[0]

    assert vulnerability.package.ecosystem == "pip"
    assert vulnerability.package.name == "requests"
    assert vulnerability.vulnerable_version_range == "<2.32.0"
    assert vulnerability.first_patched_version == "2.32.0"


def test_parse_vulnerability_without_patched_version() -> None:
    parser = GitHubAdvisoryParser()

    result = parser.parse(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
            "vulnerabilities": [
                {
                    "package": {
                        "ecosystem": "go",
                        "name": "example.com/project",
                    },
                    "vulnerable_version_range": "<1.5.0",
                },
            ],
        },
    )

    assert result is not None
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].first_patched_version is None
    assert result.vulnerabilities[0].vulnerable_functions == []


def test_parse_cvss() -> None:
    parser = GitHubAdvisoryParser()

    result = parser.parse(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
            "cvss": {
                "score": 7.5,
                "vector_string": "CVSS:3.1/AV:N",
            },
        },
    )

    assert result is not None
    assert result.cvss is not None
    assert result.cvss.score == 7.5
    assert result.cvss.vector_string == "CVSS:3.1/AV:N"


def test_parse_cvss_ignores_invalid_score() -> None:
    parser = GitHubAdvisoryParser()

    result = parser.parse(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
            "cvss": {
                "score": "invalid",
                "vector_string": "CVSS:3.1/AV:N",
            },
        },
    )

    assert result is not None
    assert result.cvss is not None
    assert result.cvss.score is None
    assert result.cvss.vector_string == "CVSS:3.1/AV:N"


def test_parse_cvss_severities() -> None:
    parser = GitHubAdvisoryParser()

    result = parser.parse(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
            "cvss_severities": {
                "cvss_v3": {
                    "score": 7.5,
                },
                "cvss_v4": {
                    "score": 8.8,
                },
            },
        },
    )

    assert result is not None
    assert result.cvss_severities is not None
    assert result.cvss_severities.cvss_v3 is not None
    assert result.cvss_severities.cvss_v4 is not None
    assert result.cvss_severities.cvss_v3.score == 7.5
    assert result.cvss_severities.cvss_v4.score == 8.8


def test_parse_empty_cvss_severities_returns_none() -> None:
    parser = GitHubAdvisoryParser()

    result = parser.parse(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
            "cvss_severities": {},
        },
    )

    assert result is not None
    assert result.cvss_severities is None


def test_parse_references_ignores_invalid_items() -> None:
    parser = GitHubAdvisoryParser()

    result = parser.parse(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
            "references": [
                "https://example.com/1",
                "https://example.com/2",
                123,
                None,
            ],
        },
    )

    assert result is not None
    assert result.references == [
        "https://example.com/1",
        "https://example.com/2",
    ]


def test_parse_non_list_identifiers_returns_empty() -> None:
    parser = GitHubAdvisoryParser()

    result = parser.parse(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
            "identifiers": {},
        },
    )

    assert result is not None
    assert result.identifiers == []


def test_parse_non_list_vulnerabilities_returns_empty() -> None:
    parser = GitHubAdvisoryParser()

    result = parser.parse(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
            "vulnerabilities": {},
        },
    )

    assert result is not None
    assert result.vulnerabilities == []


def test_parse_non_list_references_returns_empty() -> None:
    parser = GitHubAdvisoryParser()

    result = parser.parse(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
            "references": {},
        },
    )

    assert result is not None
    assert result.references == []
