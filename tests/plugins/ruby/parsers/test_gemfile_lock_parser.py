from pathlib import Path

from sentinel.enums.dependency_source_priority import DependencySourcePriority
from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.ruby.parsers.gemfile_lock_parser import GemfileLockParser


def test_supports_existing_file(tmp_path: Path) -> None:
    (tmp_path / "Gemfile.lock").write_text(
        "GEM\n",
        encoding="utf-8",
    )

    parser = GemfileLockParser()

    assert parser.supports(tmp_path) is True


def test_supports_missing_file(tmp_path: Path) -> None:
    parser = GemfileLockParser()

    assert parser.supports(tmp_path) is False


def test_parse_gem_specs(tmp_path: Path) -> None:
    (tmp_path / "Gemfile.lock").write_text(
        """\
GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.1.5)
    actionmailbox (7.1.5)
    nokogiri (1.16.7)
    rails (7.1.5)
""",
        encoding="utf-8",
    )

    parser = GemfileLockParser()

    dependencies = parser.parse(tmp_path)

    assert [(d.name, d.version) for d in dependencies] == [
        ("actioncable", "7.1.5"),
        ("actionmailbox", "7.1.5"),
        ("nokogiri", "1.16.7"),
        ("rails", "7.1.5"),
    ]


def test_parse_ignores_nested_dependencies(tmp_path: Path) -> None:
    (tmp_path / "Gemfile.lock").write_text(
        """\
GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.7)
      racc (~> 1.4)
    rails (7.1.5)
      actioncable (= 7.1.5)
      actionpack (= 7.1.5)
""",
        encoding="utf-8",
    )

    parser = GemfileLockParser()

    dependencies = parser.parse(tmp_path)

    assert [(d.name, d.version) for d in dependencies] == [
        ("nokogiri", "1.16.7"),
        ("rails", "7.1.5"),
    ]


def test_parse_multiple_specs(tmp_path: Path) -> None:
    (tmp_path / "Gemfile.lock").write_text(
        """\
GEM
  remote: https://rubygems.org/
  specs:
    rack (3.1.8)
    puma (6.4.2)
    sinatra (4.0.0)
      rack (~> 3.0)
      tilt (~> 2.0)
""",
        encoding="utf-8",
    )

    parser = GemfileLockParser()

    dependencies = parser.parse(tmp_path)

    assert [(d.name, d.version) for d in dependencies] == [
        ("rack", "3.1.8"),
        ("puma", "6.4.2"),
        ("sinatra", "4.0.0"),
    ]


def test_parse_stops_at_next_section(tmp_path: Path) -> None:
    (tmp_path / "Gemfile.lock").write_text(
        """\
GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.5)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  rails
""",
        encoding="utf-8",
    )

    parser = GemfileLockParser()

    dependencies = parser.parse(tmp_path)

    assert [(d.name, d.version) for d in dependencies] == [
        ("rails", "7.1.5"),
    ]


def test_parse_ignores_platforms_and_dependencies(tmp_path: Path) -> None:
    (tmp_path / "Gemfile.lock").write_text(
        """\
GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.5)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.1)
""",
        encoding="utf-8",
    )

    parser = GemfileLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "rails"
    assert dependencies[0].version == "7.1.5"


def test_parse_preserves_platform_version_suffix(tmp_path: Path) -> None:
    (tmp_path / "Gemfile.lock").write_text(
        """\
GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.7-x86_64-linux)
""",
        encoding="utf-8",
    )

    parser = GemfileLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1
    assert dependencies[0].name == "nokogiri"
    assert dependencies[0].version == "1.16.7-x86_64-linux"


def test_parse_empty_lockfile(tmp_path: Path) -> None:
    (tmp_path / "Gemfile.lock").write_text(
        "",
        encoding="utf-8",
    )

    parser = GemfileLockParser()

    assert parser.parse(tmp_path) == []


def test_parse_without_specs_section(tmp_path: Path) -> None:
    (tmp_path / "Gemfile.lock").write_text(
        """\
GEM
  remote: https://rubygems.org/

PLATFORMS
  ruby

DEPENDENCIES
  rails
""",
        encoding="utf-8",
    )

    parser = GemfileLockParser()

    assert parser.parse(tmp_path) == []


def test_parse_dependency_metadata(tmp_path: Path) -> None:
    (tmp_path / "Gemfile.lock").write_text(
        """\
GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.5)
""",
        encoding="utf-8",
    )

    parser = GemfileLockParser()

    dependencies = parser.parse(tmp_path)

    assert len(dependencies) == 1

    dependency = dependencies[0]

    assert dependency.name == "rails"
    assert dependency.version == "7.1.5"
    assert dependency.ecosystem is Ecosystem.RUBYGEMS
    assert dependency.source == "Gemfile.lock"
    assert dependency.priority is DependencySourcePriority.LOCK_FILE
