from sentinel.config.settings import Settings


def test_settings_defaults():
    settings = Settings()

    assert settings.app_name == "Sentinel"
    # assert settings.app_version == "1.0.-dev"
    assert settings.log_level == "INFO"
    assert settings.user_agent == "Sentinel"
    # assert settings.debug is False

    assert settings.database_url == "sqlite:///database/sentinel.db"
    assert settings.workspace == "workspace"
    assert settings.report_path == "reports"
    assert settings.export_path == "exports"
    assert settings.database_dir == "database"
    assert settings.logs_dir == "logs"
    assert settings.cache == "cache"
    assert settings.tests == "tests"

    # assert settings.max_workers == 4
    # assert settings.max_retries == 3

    # assert settings.osv_enabled is True
    assert settings.osv_base_url == "https://api.osv.dev/v1/query"
    assert settings.osv_default_timeout == 30

    # assert settings.nvd_enabled is True
    assert (
        settings.nvd_base_url
        == "https://services.nvd.nist.gov/rest/json/cves/2.0"
    )
    assert settings.nvd_default_timeout == 30

    # assert settings.ghsa_enabled is True
    assert settings.ghsa_base_url == "https://api.github.com/graphql"
    assert settings.ghsa_default_timeout == 30
    # assert settings.kev_enabled is True
    assert settings.kev_base_url == (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    assert settings.kev_default_timeout == 30

    # assert settings.epss_enabled is False
    assert settings.epss_base_url == "https://api.first.org/data/v1/epss"
    assert settings.epss_default_timeout == 30

    # assert settings.gitlab_url == ""
    # assert settings.gitlab_token == ""
