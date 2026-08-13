from __future__ import annotations

import importlib.util
import hashlib
import json
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "submission_gate_setup.py"
sys.path.insert(0, str(SRC_ROOT))


def _load_module():
    spec = importlib.util.spec_from_file_location("submission_gate_setup", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeController:
    def preflight(self):
        return {"ready": True}

    def run_once(self):
        return {"status": "ready", "processed": 0}

    def doctor(self):
        return {"ready": True}


class FakeScheduler:
    def install(self, *, mode: str):
        return {"status": "ready", "mode": mode, "installed": True}


def test_setup_creates_one_config_with_at_most_four_prompts(tmp_path: Path) -> None:
    module = _load_module()
    dependency_lock = tmp_path / "dependency-lock.json"
    dependency_lock.write_text(json.dumps({"plugins": []}), encoding="utf-8")
    prompts: list[str] = []
    setup = module.SubmissionGateSetup(
        config_path=tmp_path / "config.json",
        repo_root=tmp_path,
        bootstrap_runner=lambda profile, *, repo_root: {"status": "ready", "dependency_lock": str(dependency_lock), "profile": profile, "repo_root": str(repo_root)},
        account_discoverer=lambda _lock, _digest: {"accounts": [{"name": "gate-mail", "email": "submission-gate@example.com"}]},
        controller_factory=lambda _path: FakeController(),
        scheduler_factory=lambda _path: FakeScheduler(),
        input_fn=lambda prompt: prompts.append(prompt)
        or {
            1: "qa@example.com",
            2: "rd@example.com",
            3: "https://gitlab.example.test",
            4: "59",
        }[len(prompts)],
    )
    result = setup.run(non_interactive=False, scheduler_mode="auto")
    payload = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert result["status"] == "ready"
    assert len(prompts) == 4
    assert payload["gate_mail_account"] == {"profile": "gate-mail", "email": "submission-gate@example.com"}
    assert payload["submission_group_address"] == "qa@example.com"
    assert payload["blocked_notice_address"] == "rd@example.com"


def test_setup_non_interactive_requires_mail_groups(tmp_path: Path) -> None:
    module = _load_module()
    dependency_lock = tmp_path / "dependency-lock.json"
    dependency_lock.write_text(json.dumps({"plugins": []}), encoding="utf-8")
    setup = module.SubmissionGateSetup(
        config_path=tmp_path / "config.json",
        repo_root=tmp_path,
        bootstrap_runner=lambda profile, *, repo_root: {"status": "ready", "dependency_lock": str(dependency_lock), "profile": profile, "repo_root": str(repo_root)},
        account_discoverer=lambda _lock, _digest: {"accounts": [{"name": "gate-mail", "email": "submission-gate@example.com"}]},
        input_fn=lambda _prompt: (_ for _ in ()).throw(AssertionError("must not prompt")),
    )
    try:
        setup.run(non_interactive=True, scheduler_mode="auto")
    except Exception as exc:
        assert getattr(exc, "code", "") == "SETUP_INPUT_REQUIRED"
    else:
        raise AssertionError("non-interactive setup should require submission_group_address")


def test_setup_generates_locked_gitlab_adapter_without_secret(tmp_path: Path) -> None:
    module = _load_module()
    dependency_lock = tmp_path / "dependency-lock.json"
    dependency_lock.write_text(json.dumps({"plugins": []}), encoding="utf-8")
    setup = module.SubmissionGateSetup(
        config_path=tmp_path / "managed" / "config.json",
        repo_root=PLUGIN_ROOT.parents[1],
        bootstrap_runner=lambda profile, *, repo_root: {
            "status": "ready",
            "dependency_lock": str(dependency_lock),
            "profile": profile,
            "repo_root": str(repo_root),
        },
        account_discoverer=lambda _lock, _digest: {
            "accounts": [
                {"name": "gate-mail", "email": "submission-gate@example.com"}
            ]
        },
    )

    setup.run(
        non_interactive=True,
        scheduler_mode="auto",
        provided={
            "submission_group_address": "qa@example.com",
            "blocked_notice_address": "rd@example.com",
            "gitlab_base_url": "https://gitlab.example.test",
            "gitlab_project_id": 59,
        },
    )

    payload = json.loads(setup.config_path.read_text(encoding="utf-8"))
    adapter_config_path = Path(payload["gitlab_gate_adapter_config"])
    adapter_config = json.loads(adapter_config_path.read_text(encoding="utf-8"))
    entrypoint = PLUGIN_ROOT / "src" / "gitlab_gate_adapter.py"
    expected_command = [
        sys.executable,
        str(entrypoint.resolve()),
        "--config",
        str(adapter_config_path.resolve()),
    ]
    assert payload["gate_adapter"]["command"] == expected_command
    assert payload["gate_adapter"]["preflight_command"] == expected_command + [
        "--preflight"
    ]
    assert payload["gate_adapter"]["entrypoint_path"] == str(entrypoint.resolve())
    assert payload["gate_adapter"]["entrypoint_sha256"] == hashlib.sha256(
        entrypoint.read_bytes()
    ).hexdigest()
    integrity_files = {
        Path(item["path"]): item["sha256"]
        for item in payload["gate_adapter"]["integrity_files"]
    }
    assert integrity_files[adapter_config_path.resolve()] == hashlib.sha256(
        adapter_config_path.read_bytes()
    ).hexdigest()
    contract_path = (
        PLUGIN_ROOT / "src" / "release_workflow_core" / "gate_adapter_contract.py"
    ).resolve()
    assert integrity_files[contract_path] == hashlib.sha256(
        contract_path.read_bytes()
    ).hexdigest()
    assert adapter_config["token_env"] == "PMG_GITLAB_TOKEN"
    assert "token" not in adapter_config
    assert "secret" not in json.dumps(adapter_config).lower()
