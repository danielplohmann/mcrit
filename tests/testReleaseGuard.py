"""The release gate (`.github/workflows/scripts/release_guard.py`) runs once per release, minutes
before the artefact becomes permanent, so here is the only place its checks can be exercised
before they matter. It also holds the one test tying `McritConfig.VERSION` to `pyproject.toml`."""

import importlib.util
import tomllib
from pathlib import Path

import pytest

from mcrit.config.McritConfig import McritConfig

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / ".github" / "workflows" / "scripts" / "release_guard.py"

CHANGELOG = """# Changelog

## [Unreleased]

### Fixed

- something not yet released.

## [1.10.0] - 2026-09-20

### Changed

- the thing this release did.

## [1.10.0rc1] - 2026-09-15

### Added

- the candidate.

## [1.9.0] - 2026-09-08

### Fixed

- an older release.
"""


@pytest.fixture(scope="module")
def guard():
    if not SCRIPT.exists():
        pytest.skip("running outside a source tree")
    spec = importlib.util.spec_from_file_location("release_guard", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tree(tmp_path: Path, version: str, changelog: str = CHANGELOG) -> Path:
    (tmp_path / "pyproject.toml").write_text(f'[project]\nname = "mcrit"\nversion = "{version}"\n')
    (tmp_path / "mcrit" / "config").mkdir(parents=True)
    (tmp_path / "mcrit" / "config" / "McritConfig.py").write_text(f'class McritConfig:\n    VERSION = "{version}"\n')
    (tmp_path / "CHANGELOG.md").write_text(changelog)
    return tmp_path


def test_config_version_equals_the_packaged_version():
    pyproject = ROOT / "pyproject.toml"
    if not pyproject.exists():
        pytest.skip("running outside a source tree")
    assert McritConfig.VERSION == tomllib.loads(pyproject.read_text())["project"]["version"]


def test_the_section_for_a_version_is_returned_and_stops_at_the_next(guard):
    notes = guard.changelogSection(CHANGELOG, "1.10.0")
    assert "the thing this release did" in notes
    assert "the candidate" not in notes
    assert "not yet released" not in notes


def test_a_missing_or_empty_or_undated_section_fails(guard):
    with pytest.raises(SystemExit, match="Unreleased"):
        guard.changelogSection(CHANGELOG, "1.11.0")
    with pytest.raises(SystemExit, match="nothing under it"):
        guard.changelogSection("# Changelog\n\n## [9.0.0] - 2026-01-01\n\n## [8.0.0] - 2025-01-01\n\n- x\n", "9.0.0")
    with pytest.raises(SystemExit):
        guard.changelogSection("# Changelog\n\n## [9.0.0]\n\n- something.\n", "9.0.0")


def test_the_declared_versions_in_this_tree_agree(guard):
    versions = guard.declaredVersions(ROOT)
    assert set(versions) == {"pyproject.toml", "McritConfig.VERSION"}
    assert len(set(versions.values())) == 1


def test_a_matching_tag_passes_and_writes_notes_and_outputs(guard, tmp_path):
    root = _tree(tmp_path, "1.10.0")
    notes, output = root / "notes.md", root / "output.txt"
    argv = ["--tag", "v1.10.0", "--root", str(root), "--notes", str(notes), "--github-output", str(output)]
    assert guard.main(argv) == 0
    assert "the thing this release did" in notes.read_text()
    assert output.read_text() == "version=1.10.0\nprerelease=false\n"


def test_a_pre_release_tag_is_flagged(guard, tmp_path):
    root = _tree(tmp_path, "1.10.0rc1")
    output = root / "output.txt"
    assert guard.main(["--tag", "v1.10.0rc1", "--root", str(root), "--github-output", str(output)]) == 0
    assert "prerelease=true" in output.read_text()


@pytest.mark.parametrize("tag", ["1.10.0", "v1.10", "v1.10.0-rc1", "v1.10.0.dev1", "vlatest"])
def test_a_malformed_tag_fails(guard, tmp_path, tag):
    root = _tree(tmp_path, "1.10.0")
    with pytest.raises(SystemExit):
        guard.main(["--tag", tag, "--root", str(root)])


def test_a_tag_disagreeing_with_any_declared_version_fails(guard, tmp_path):
    root = _tree(tmp_path, "1.9.0")
    with pytest.raises(SystemExit, match=r"1\.9\.0"):
        guard.main(["--tag", "v1.10.0", "--root", str(root)])
    (root / "pyproject.toml").write_text('[project]\nname = "mcrit"\nversion = "1.10.0"\n')
    with pytest.raises(SystemExit, match=r"McritConfig\.VERSION = 1\.9\.0"):
        guard.main(["--tag", "v1.10.0", "--root", str(root)])
