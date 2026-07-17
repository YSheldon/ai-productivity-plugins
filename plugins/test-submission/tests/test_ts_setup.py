from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "test_submission_setup.py"
sys.path.insert(0, str(SRC_ROOT))


def _load_module():
    spec = importlib.util.spec_from_file_location("test_submission_setup", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeController:
    def preflight(self) -> dict[str, object]:
        return {"ready": True}

    def run_once(self) -> dict[str, object]:
        return {"status": "ready", "retried": 0, "sent": 0}

    def doctor(self) -> dict[str, object]:
        return {"ready": True}


class FakeScheduler:
    def install(self, *, mode: str) -> dict[str, object]:
        return {"status": "ready", "mode": mode, "installed": True}


def test_setup_creates_one_config_with_at_most_four_prompts(tmp_path: Path) -> None:
    module = _load_module()
    dependency_lock = tmp_path / "dependency-lock.json"
    dependency_lock.write_text(json.dumps({"plugins": []}), encoding="utf-8")
    prompts: list[str] = []

    setup = module.TestSubmissionSetup(
        config_path=tmp_path / "config.json",
        repo_root=tmp_path,
        bootstrap_runner=lambda profile, *, repo_root: {"status": "ready", "dependency_lock": str(dependency_lock), "profile": profile, "repo_root": str(repo_root)},
        account_discoverer=lambda _lock, _digest: {"accounts": [{"name": "mail-primary", "email": "submitter@example.com"}]},
        controller_factory=lambda _path: FakeController(),
        scheduler_factory=lambda _path: FakeScheduler(),
        input_fn=lambda prompt: prompts.append(prompt) or ("submission-gate@example.com" if len(prompts) == 1 else "https://open.feishu.cn/wiki/materials"),
    )

    result = setup.run(non_interactive=False, scheduler_mode="auto")
    payload = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert result["status"] == "ready"
    assert len(prompts) == 2
    assert payload["mail_account"] == {"profile": "mail-primary", "email": "submitter@example.com"}
    assert payload["submission_gate_address"] == "submission-gate@example.com"
    assert payload["dependency_lock_sha256"] == module.sha256_file(dependency_lock)


def test_setup_rerun_uses_existing_config_with_zero_prompts(tmp_path: Path) -> None:
    module = _load_module()
    dependency_lock = tmp_path / "dependency-lock.json"
    dependency_lock.write_text(json.dumps({"plugins": []}), encoding="utf-8")
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "mail_account": {"profile": "mail-primary", "email": "submitter@example.com"},
                "submission_gate_address": "submission-gate@example.com",
                "dependency_lock": str(dependency_lock),
                "dependency_lock_sha256": module.sha256_file(dependency_lock),
            }
        ),
        encoding="utf-8",
    )
    setup = module.TestSubmissionSetup(
        config_path=config_path,
        repo_root=tmp_path,
        bootstrap_runner=lambda profile, *, repo_root: {"status": "ready", "dependency_lock": str(dependency_lock), "profile": profile, "repo_root": str(repo_root)},
        account_discoverer=lambda _lock, _digest: (_ for _ in ()).throw(AssertionError("must not rediscover")),
        input_fn=lambda _prompt: (_ for _ in ()).throw(AssertionError("must not prompt")),
    )
    assert setup.run(non_interactive=False, scheduler_mode="auto")["prompt_count"] == 0


def test_setup_non_interactive_requires_gate_address(tmp_path: Path) -> None:
    module = _load_module()
    dependency_lock = tmp_path / "dependency-lock.json"
    dependency_lock.write_text(json.dumps({"plugins": []}), encoding="utf-8")
    setup = module.TestSubmissionSetup(
        config_path=tmp_path / "config.json",
        repo_root=tmp_path,
        bootstrap_runner=lambda profile, *, repo_root: {"status": "ready", "dependency_lock": str(dependency_lock), "profile": profile, "repo_root": str(repo_root)},
        account_discoverer=lambda _lock, _digest: {"accounts": [{"name": "mail-primary", "email": "submitter@example.com"}]},
        input_fn=lambda _prompt: (_ for _ in ()).throw(AssertionError("must not prompt")),
    )
    try:
        setup.run(non_interactive=True, scheduler_mode="auto")
    except Exception as exc:
        assert getattr(exc, "code", "") == "SETUP_INPUT_REQUIRED"
    else:
        raise AssertionError("non-interactive setup should require submission_gate_address")
