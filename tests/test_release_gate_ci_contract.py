from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release-gate-ci.yml"


def test_release_gate_ci_runs_the_full_pytest_workflow_suite() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    assert "python -m pytest -q --tb=short --junitxml=artifacts/release-gate-ci/junit.xml" in source
    assert "python -m unittest discover" not in source
    assert "actions/upload-artifact@v4" in source
    assert "path: artifacts/release-gate-ci/junit.xml" in source
    assert "if-no-files-found: error" in source


def test_release_gate_ci_triggers_for_every_release_workflow_component() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    expected_paths = (
        "contracts/release-approval/**",
        "shared/release_workflow_core/**",
        "plugins/imap-smtp-mail/**",
        "plugins/test-submission/**",
        "plugins/submission-gate/**",
        "plugins/pre-release/**",
        "plugins/release-gate/**",
        "plugins/release-approval/**",
        "plugins/release-approval-verifier/**",
        "plugins/product-release-gate/**",
        "plugins/rd-flywheel/**",
        "plugins/gitlab/**",
        "tests/test_release_workflow_*.py",
        "tests/test_release_approval_*.py",
        "tests/test_product_material_workflow_*.py",
        "tools/sync_release_workflow_core.py",
    )

    for path in expected_paths:
        assert source.count(path) == 2, path
