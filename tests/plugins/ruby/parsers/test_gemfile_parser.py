from pathlib import Path

from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.ruby.parsers.gemfile_parser import GemfileParser


def test_supports_gemfile(
    tmp_path: Path,
) -> None:
    (tmp_path / "Gemfile").write_text(
        'gem "rails"\n',
        encoding="utf-8",
    )

    parser = GemfileParser()

    assert parser.supports(tmp_path) is True


def test_does_not_support_missing_gemfile(
    tmp_path: Path,
) -> None:
    parser = GemfileParser()

    assert parser.supports(tmp_path) is False


def test_parse_gem_without_version(
    tmp_path: Path,
) -> None:
    (tmp_path / "Gemfile").write_text(
        'gem "rails"\n',
        encoding="utf-8",
    )

    parser = GemfileParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "rails"
    assert dependency.version == "*"
    assert dependency.ecosystem == Ecosystem.RUBYGEMS
    assert dependency.source == "Gemfile"
    assert dependency.priority == DependencySourcePriority.MANIFEST


def test_parse_gem_with_version_constraint(
    tmp_path: Path,
) -> None:
    (tmp_path / "Gemfile").write_text(
        'gem "rails", "~> 7.1"\n',
        encoding="utf-8",
    )

    parser = GemfileParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "rails"
    assert dependency.version == "~> 7.1"
    assert dependency.ecosystem == Ecosystem.RUBYGEMS


def test_parse_gem_with_minimum_version(
    tmp_path: Path,
) -> None:
    (tmp_path / "Gemfile").write_text(
        'gem "nokogiri", ">= 1.15"\n',
        encoding="utf-8",
    )

    parser = GemfileParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    assert dependencies[0].name == "nokogiri"
    assert dependencies[0].version == ">= 1.15"


def test_parse_gem_with_require_option(
    tmp_path: Path,
) -> None:
    (tmp_path / "Gemfile").write_text(
        'gem "rack", "~> 3.0", require: false\n',
        encoding="utf-8",
    )

    parser = GemfileParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    assert dependencies[0].name == "rack"
    assert dependencies[0].version == "~> 3.0"


def test_parse_multiple_gems(
    tmp_path: Path,
) -> None:
    (tmp_path / "Gemfile").write_text(
        """
gem "rails", "~> 7.1"
gem "nokogiri", ">= 1.15"
gem "rack"
""",
        encoding="utf-8",
    )

    parser = GemfileParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 3

    assert dependencies[0].name == "rails"
    assert dependencies[0].version == "~> 7.1"

    assert dependencies[1].name == "nokogiri"
    assert dependencies[1].version == ">= 1.15"

    assert dependencies[2].name == "rack"
    assert dependencies[2].version == "*"


def test_parse_gems_inside_group(
    tmp_path: Path,
) -> None:
    (tmp_path / "Gemfile").write_text(
        """
group :development do
  gem "rubocop", "~> 1.60"
end
""",
        encoding="utf-8",
    )

    parser = GemfileParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    assert dependencies[0].name == "rubocop"
    assert dependencies[0].version == "~> 1.60"


def test_ignore_comments(
    tmp_path: Path,
) -> None:
    (tmp_path / "Gemfile").write_text(
        """
# gem "rails", "~> 7.1"
gem "rack"
""",
        encoding="utf-8",
    )

    parser = GemfileParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "rack"


def test_ignore_non_gem_lines(
    tmp_path: Path,
) -> None:
    (tmp_path / "Gemfile").write_text(
        """
source "https://rubygems.org"

ruby "3.3.0"

gem "rails", "~> 7.1"
""",
        encoding="utf-8",
    )

    parser = GemfileParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "rails"


def test_parse_parenthesized_gem(
    tmp_path: Path,
) -> None:
    (tmp_path / "Gemfile").write_text(
        'gem("rails", "~> 7.1")\n',
        encoding="utf-8",
    )

    parser = GemfileParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    assert dependencies[0].name == "rails"
    assert dependencies[0].version == "~> 7.1"


def test_parse_single_quotes(
    tmp_path: Path,
) -> None:
    (tmp_path / "Gemfile").write_text(
        "gem 'rails', '~> 7.1'\n",
        encoding="utf-8",
    )

    parser = GemfileParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    assert dependencies[0].name == "rails"
    assert dependencies[0].version == "~> 7.1"


def test_empty_gemfile(
    tmp_path: Path,
) -> None:
    (tmp_path / "Gemfile").write_text(
        "",
        encoding="utf-8",
    )

    parser = GemfileParser()

    dependencies = parser.parse(tmp_path)

    assert dependencies == []


def test_ignore_empty_lines(
    tmp_path: Path,
) -> None:
    (tmp_path / "Gemfile").write_text(
        """

gem "rails"

# comment

gem "rack", "~> 3.0"

""",
        encoding="utf-8",
    )

    parser = GemfileParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 2

    assert dependencies[0].name == "rails"
    assert dependencies[1].name == "rack"
