from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "sync_release_workflow_core.py"
PLUGIN_NAMES = ("test-submission", "submission-gate", "pre-release", "release-gate")


def _fixture_repo(tmp_path: Path, *, create_targets: bool = True) -> Path:
    repo = tmp_path / "repo"
    source = repo / "shared" / "release_workflow_core"
    source.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / "shared" / "release_workflow_core", source)
    for plugin_name in PLUGIN_NAMES:
        plugin_src = repo / "plugins" / plugin_name / "src"
        plugin_src.mkdir(parents=True, exist_ok=True)
        if create_targets:
            (plugin_src / "release_workflow_core").mkdir(parents=True, exist_ok=True)
    return repo


def _run(*args: str, repo_root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), "--repo-root", str(repo_root), *args],
        text=True,
        capture_output=True,
        check=False,
    )


def test_sync_writes_embedded_copies_to_all_four_plugins(tmp_path: Path) -> None:
    repo = _fixture_repo(tmp_path)
    result = _run(repo_root=repo)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    for plugin_name in PLUGIN_NAMES:
        payload = report["plugins"][plugin_name]
        assert payload["status"] == "synced"
        target_root = repo / "plugins" / plugin_name / "src" / "release_workflow_core"
        assert (target_root / "__init__.py").is_file()
        assert (target_root / "audit.py").read_bytes() == (
            repo / "shared" / "release_workflow_core" / "audit.py"
        ).read_bytes()


def test_sync_check_and_drift_report_detect_modified_embedded_copy(tmp_path: Path) -> None:
    repo = _fixture_repo(tmp_path)
    sync_result = _run(repo_root=repo)
    assert sync_result.returncode == 0

    clean_check = _run("--check", repo_root=repo)
    assert clean_check.returncode == 0
    clean_report = json.loads(clean_check.stdout)
    assert clean_report["plugins"]["release-gate"]["status"] == "clean"

    tampered = repo / "plugins" / "release-gate" / "src" / "release_workflow_core" / "version.py"
    tampered.write_text('CORE_VERSION = "drifted"\n', encoding="utf-8")
    drift = _run("--drift", repo_root=repo)
    assert drift.returncode == 1
    drift_report = json.loads(drift.stdout)
    assert drift_report["plugins"]["release-gate"]["status"] == "drift"
    assert drift_report["plugins"]["release-gate"]["changed"] == ["version.py"]


def test_sync_can_skip_missing_embedded_target_only_with_explicit_flag(tmp_path: Path) -> None:
    repo = _fixture_repo(tmp_path, create_targets=False)
    missing_check = _run("--check", repo_root=repo)
    assert missing_check.returncode == 1
    missing_report = json.loads(missing_check.stdout)
    assert missing_report["plugins"]["test-submission"]["status"] == "drift"

    allowed = _run("--check", "--allow-missing-targets", repo_root=repo)
    assert allowed.returncode == 0
    allowed_report = json.loads(allowed.stdout)
    assert allowed_report["plugins"]["test-submission"]["status"] == "skipped"
