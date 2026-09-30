from pydantic import Field
from pydantic_settings import BaseSettings
from pydantic_settings import SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = Field(default="Sentinel", alias="APP_NAME")

    app_version: str = Field(default="1.0.0", alias="APP_VERSION")

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    user_agent: str = "Sentinel"

    debug: bool = Field(default=False, alias="DEBUG")

    database_url: str = Field(
        default="sqlite:///database/sentinel.db", alias="DATABASE_URL"
    )
    # repertoires de travail
    workspace: str = Field(default="workspace", alias="WORKSPACE")
    report_path: str = Field(default="reports", alias="REPORT_PATH")
    export_path: str = Field(default="exports", alias="EXPORT_PATH")
    database_dir: str = Field(default="database", alias="DATABASE")
    logs_dir: str = Field(default="logs", alias="LOGS")
    cache: str = Field(default="cache", alias="CACHE")
    tests: str = Field(default="tests", alias="TESTS")

    max_workers: int = Field(default=4, alias="MAX_WORKERS")
    max_retries: int = Field(default=3, alias="MAX_RETRIES")

    # API Authentication / JWT
    api_jwt_secret: str = Field(
        min_length=32,
        default="JKfYIx+1lRY7mh(aBQT293%An==?=CO%J(P&8+kh#p%",
        alias="API_JWT_SECRET",
    )

    api_jwt_algorithm: str = Field(
        default="HS256",
        alias="API_JWT_ALGORITHM",
    )

    api_access_token_expire_minutes: int = Field(
        default=30,
        alias="API_ACCESS_TOKEN_EXPIRE_MINUTES",
        gt=0,
    )

    # Providers
    # OSV
    osv_enabled: bool = Field(default=True, alias="OSV_ENABLED")
    osv_base_url: str = Field(
        default="https://api.osv.dev/v1/query", alias="OSV_BASE_URL"
    )
    osv_default_timeout: int = Field(default=30, alias="OSV_DEFAULT_TIMEOUT")

    # NVD
    nvd_enabled: bool = Field(default=True, alias="NVD_ENABLED")

    nvd_base_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        alias="NVD_BASE_URL",
    )

    nvd_api_key: str = Field(default="", alias="NVD_API_KEY")

    nvd_default_timeout: int = Field(default=30, alias="NVD_DEFAULT_TIMEOUT")

    nvd_min_request_interval: float = Field(
        default=0.6,
        alias="NVD_MIN_REQUEST_INTERVAL",
        ge=0,
    )

    nvd_max_retries: int = Field(
        default=3,
        alias="NVD_MAX_RETRIES",
        ge=0,
    )

    nvd_retry_backoff: float = Field(
        default=1.0,
        alias="NVD_RETRY_BACKOFF",
        gt=0,
    )

    # GHSA
    ghsa_enabled: bool = Field(default=True, alias="GHSA_ENABLED")
    ghsa_base_url: str = Field(
        default="https://api.github.com/advisories",
        alias="GHSA_BASE_URL"
    )
    ghsa_default_timeout: int = Field(default=30, alias="GHSA_DFAULT_TIMEOUT")
    ghsa_token: str = Field(default="", alias="GHSA_TOKEN")

    # GitHub Global Security Advisory
    github_advisory_enabled: bool = Field(
        default=True,
        alias="GITHUB_ADVISORY_ENABLED",
    )
    github_advisory_base_url: str = Field(
        default="https://api.github.com",
        alias="GITHUB_ADVISORY_BASE_URL",
    )
    github_advisory_token: str = Field(
        default="",
        alias="GITHUB_ADVISORY_TOKEN",
    )
    github_advisory_default_timeout: int = Field(
        default=30,
        alias="GITHUB_ADVISORY_DEFAULT_TIMEOUT",
    )

    # CISA KEV
    kev_enabled: bool = Field(default=True, alias="KEV_ENABLED")
    kev_base_url: str = Field(
        default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        alias="KEV_BASE_URL",
    )
    kev_default_timeout: int = Field(default=30, alias="KEV_DEFAULT_TIMEOUT")

    # EPSS
    epss_enabled: bool = Field(default=False, alias="EPSS_ENABLED")
    epss_base_url: str = Field(
        default="https://api.first.org/data/v1/epss", alias="EPSS_BASE_URL"
    )
    epss_default_timeout: int = Field(default=30, alias="EPSS_DEFAULT_TIMEOUT")
    epss_batch_size: int = Field(
        default=100,
        alias="EPSS_BATCH_SIZE",
        gt=0,
    )

    # VulnCheck KEV
    vulncheck_kev_enabled: bool = Field(
        default=False,
        alias="VULNCHECK_KEV_ENABLED",
    )

    vulncheck_kev_base_url: str = Field(
        default="https://api.vulncheck.com/v3",
        alias="VULNCHECK_KEV_BASE_URL",
    )

    vulncheck_kev_api_token: str = Field(
        default="",
        alias="VULNCHECK_KEV_API_TOKEN",
    )

    vulncheck_kev_default_timeout: int = Field(
        default=30,
        alias="VULNCHECK_KEV_DEFAULT_TIMEOUT",
    )

    # Forges
    git_forge: str | None = Field(
        default=None,
        alias="GIT_FORGE",
    )
    # GITLAB
    gitlab_url: str = ""

    gitlab_token: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
        extra="ignore",  # <-- IMPORTANT
    )


settings = Settings()
