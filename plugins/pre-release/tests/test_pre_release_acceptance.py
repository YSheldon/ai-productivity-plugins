from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from pre_release_config import MailAccountConfig, PreReleaseConfig, ProductGateConfig
from pre_release_controller import PreReleaseController
from pre_release_mail import PreReleaseMailError, encode_machine_event, resolve_locked_entrypoint, sign_machine_event
from pre_release_scheduler import PreReleaseScheduler
from pre_release_setup import PreReleaseSetup


FIXED_NOW = datetime(2026, 7, 17, 3, 4, 5, tzinfo=timezone.utc)


class FakeController:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preflight(self) -> dict[str, object]:
        self.calls.append("preflight")
        return {"status": "ready", "ready": True, "missing_capabilities": [], "audit": {"valid": True}}

    def run_once(self) -> dict[str, object]:
        self.calls.append("run_once")
        return {"status": "ready", "matched_events": 0}

    def doctor(self) -> dict[str, object]:
        self.calls.append("doctor")
        return {"status": "ready", "ready": True}


class FakeMailGateway:
    def __init__(self, messages: list[dict[str, object]]) -> None:
        self.messages = messages
        self.sent: list[dict[str, object]] = []

    def search_messages(self, _arguments: dict[str, object]) -> dict[str, object]:
        return {"messages": [{"uid": message["uid"]} for message in self.messages]}

    def read_message(self, arguments: dict[str, object]) -> dict[str, object]:
        uid = str(arguments["uid"])
        return next(message for message in self.messages if message["uid"] == uid)

    def send_email(self, arguments: dict[str, object]) -> dict[str, object]:
        self.sent.append(dict(arguments))
        return {"message_id": "<pre-release@example.com>"}


class RecordingProductGate:
    def __init__(self, *, manifest_r_digest: str = "sha256:" + "b" * 64) -> None:
        self.manifest_r_digest = manifest_r_digest
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call(self, operation: str, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append((operation, dict(payload)))
        if operation == "build_final_release":
            return {
                "status": "ready",
                "manifest_r_digest": self.manifest_r_digest,
                "manifest_r_ref": "artifact://manifest-r.json",
            }
        return {"status": "ready"}


def _write_lock(repo_root: Path) -> Path:
    lock_path = repo_root / "dependency-lock.product-release-gate.json"
    (repo_root / "plugins" / "imap-smtp-mail" / "src").mkdir(parents=True, exist_ok=True)
    (repo_root / "plugins" / "product-release-gate" / "src").mkdir(parents=True, exist_ok=True)
    mail_cli = repo_root / "plugins" / "imap-smtp-mail" / "src" / "imap_smtp_mail_cli.py"
    gate_cli = repo_root / "plugins" / "product-release-gate" / "src" / "release_gate_cli.py"
    mail_cli.write_text("print('mail')\n", encoding="utf-8")
    gate_cli.write_text("print('gate')\n", encoding="utf-8")
    lock_path.write_text(
        json.dumps(
            {
                "plugins": [
                    {
                        "name": "imap-smtp-mail",
                        "plugin_root": "plugins/imap-smtp-mail",
                        "entrypoints": [{"path": "plugins/imap-smtp-mail/src/imap_smtp_mail_cli.py", "sha256": hashlib.sha256(mail_cli.read_bytes()).hexdigest()}],
                    },
                    {
                        "name": "product-release-gate",
                        "plugin_root": "plugins/product-release-gate",
                        "entrypoints": [{"path": "plugins/product-release-gate/src/release_gate_cli.py", "sha256": hashlib.sha256(gate_cli.read_bytes()).hexdigest()}],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    return lock_path


def _config(tmp_path: Path) -> PreReleaseConfig:
    secret = tmp_path / "state" / "keys" / "shared-handoff.key"
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_bytes(b"1" * 32)
    return PreReleaseConfig(
        mail_account=MailAccountConfig(profile="qa-owner", email="qa-owner@example.com"),
        submission_group="submission@example.com",
        release_gate_group="release-gate@example.com",
        mailbox="INBOX",
        timezone="UTC",
        poll_minutes=60,
        state_dir=tmp_path / "state",
        dependency_lock=tmp_path / "dependency-lock.json",
        dependency_lock_sha256="0" * 64,
        shared_hmac_secret_path=secret,
        mail_command=("py", "-3", "mail.py"),
        product_gate=ProductGateConfig(config_path=tmp_path / "product-config.json", command=("py", "-3", "gate.py")),
        policy_profile="pre-release/v1",
        enabled_optional_checks=(),
    )


def _submission_message(config: PreReleaseConfig) -> dict[str, object]:
    payload = sign_machine_event(
        {
            "contract": "ProductMaterialWorkflowEvent/v1",
            "event_type": "SUBMISSION_GATE_PASS",
            "event_id": "evt-1",
            "round_id": 2,
            "task": "Task A",
            "module": "client",
            "manifest_s_digest": "sha256:" + "a" * 64,
            "policy_digest": "sha256:" + "c" * 64,
            "gitlab_evidence_digest": "sha256:" + "d" * 64,
            "gitlab_evidence_ref": "gitlab://pipeline/1",
            "lark_evidence_ref": "lark://doc/1",
            "source_message_id": "<submission@example.com>",
            "thread_references": ["<submission@example.com>"],
            "checked_items": ["sha256", "signature", "cloud_scan"],
            "artifacts": [{"logical_name": "demo.exe"}],
        },
        config.shared_hmac_secret_path.read_bytes(),
    )
    return {
        "uid": "7",
        "message_id": "<submission@example.com>",
        "body_text": encode_machine_event(payload),
        "evidence": {
            "message_id": "<submission@example.com>",
            "references": ["<submission@example.com>"],
            "raw_headers_sha256": "a" * 64,
        },
    }


def test_setup_smoke_isolates_home_path_and_scheduler_lifecycle_without_codex(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = tmp_path / "repo"
    config_path = tmp_path / "managed" / "config.json"
    lock_path = _write_lock(repo_root)
    home = tmp_path / "isolated-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("PATH", "")

    calls: list[list[str]] = []

    def runner(command: list[str], cwd: str | None, input_text: str | None) -> subprocess.CompletedProcess[str]:
        del cwd, input_text
        calls.append(list(command))
        if command[:2] == ["schtasks", "/Query"]:
            return subprocess.CompletedProcess(
                command,
                0,
                """<?xml version=\"1.0\" encoding=\"UTF-16\"?>
<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>false</StartWhenAvailable>
  </Settings>
</Task>
""",
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    controller = FakeController()
    scheduler_holder: dict[str, PreReleaseScheduler] = {}

    def scheduler_factory(_config_path: Path, state_dir: Path, poll_minutes: int) -> PreReleaseScheduler:
        scheduler = PreReleaseScheduler(
            config_path=config_path,
            state_dir=state_dir,
            poll_minutes=poll_minutes,
            platform="win32",
            which=lambda _name: None,
            runner=runner,
            user_config_root=tmp_path / "config-root",
        )
        scheduler_holder["scheduler"] = scheduler
        return scheduler

    setup = PreReleaseSetup(
        config_path,
        repo_root=repo_root,
        bootstrap_runner=lambda **_kwargs: {"dependency_lock": str(lock_path)},
        controller_factory=lambda _config, _lock: controller,
        scheduler_factory=scheduler_factory,
    )
    result = setup.run(non_interactive=True, scheduler_mode="auto", provided={})
    assert result["status"] == "ready"
    assert result["prompt_count"] == 0
    assert controller.calls == ["preflight", "run_once", "doctor"]
    written = json.loads(config_path.read_text(encoding="utf-8"))
    assert "output_dir" not in json.dumps(written, ensure_ascii=False)
    assert "test_result_source" not in json.dumps(written, ensure_ascii=False)
    assert "codex" not in " ".join(written["mail_command"]).lower()
    scheduler = scheduler_holder["scheduler"]
    assert scheduler.status(mode="windows")["installed"] is True
    assert scheduler.remove(mode="windows")["removed"] is True
    assert any(command[:2] == ["schtasks", "/Create"] for command in calls)
    assert any(command[:2] == ["schtasks", "/Delete"] for command in calls)


def test_restart_duplicate_and_audit_tamper_fail_closed(tmp_path: Path) -> None:
    config = _config(tmp_path)
    first = PreReleaseController(
        config,
        mail_gateway=FakeMailGateway([_submission_message(config)]),
        product_gate=RecordingProductGate(),
        now_fn=lambda: FIXED_NOW,
    )
    second = PreReleaseController(
        config,
        mail_gateway=FakeMailGateway([_submission_message(config)]),
        product_gate=RecordingProductGate(),
        now_fn=lambda: FIXED_NOW,
    )
    assert first.run_once()["matched_events"] == 1
    assert second.run_once()["matched_events"] == 0
    verify = second.verify_audit()
    assert verify["valid"] is True
    entry = next((tmp_path / "state" / "audit" / "entries").glob("*.json"))
    payload = json.loads(entry.read_text(encoding="utf-8"))
    payload["payload"]["event_id"] = "tampered"
    entry.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    assert second.verify_audit()["valid"] is False
    assert second.run_once()["status"] == "CAPABILITY_BLOCKED"


def test_fail_never_builds_manifest_r_or_sends_request_and_output_dir_is_task_only(tmp_path: Path) -> None:
    config = _config(tmp_path)
    mail = FakeMailGateway([_submission_message(config)])
    product_gate = RecordingProductGate()
    controller = PreReleaseController(
        config,
        mail_gateway=mail,
        product_gate=product_gate,
        now_fn=lambda: FIXED_NOW,
    )
    controller.run_once()
    result = controller.create_request(
        event_id="evt-1",
        round_id=2,
        test_result="FAIL",
        summary="失败",
        failure_reason="冒烟失败",
    )
    task = json.loads((tmp_path / "state" / "tasks" / "evt-1--2.json").read_text(encoding="utf-8"))
    example = json.loads((PLUGIN_ROOT / "config" / "config.example.json").read_text(encoding="utf-8"))
    assert result["status"] == "TEST_FAILED"
    assert "manifest_r_digest" not in task
    assert product_gate.calls == []
    assert mail.sent == []
    assert "output_dir" not in example
    assert "test_result_source" not in example


def test_dependency_lock_drift_and_missing_manifest_r_digest_fail_closed(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    lock_path = _write_lock(repo_root)
    expected_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    assert resolve_locked_entrypoint(
        lock_path,
        dependency_lock_sha256=expected_digest,
        plugin_name="product-release-gate",
        plugin_root=Path("plugins/product-release-gate"),
        entrypoint_path=Path("plugins/product-release-gate/src/release_gate_cli.py"),
    ).name == "release_gate_cli.py"
    (repo_root / "plugins" / "product-release-gate" / "src" / "release_gate_cli.py").write_text("print('drift')\n", encoding="utf-8")
    with pytest.raises(PreReleaseMailError, match="drift"):
        resolve_locked_entrypoint(
            lock_path,
            dependency_lock_sha256=expected_digest,
            plugin_name="product-release-gate",
            plugin_root=Path("plugins/product-release-gate"),
            entrypoint_path=Path("plugins/product-release-gate/src/release_gate_cli.py"),
        )

    config = _config(tmp_path / "missing-digest")
    controller = PreReleaseController(
        config,
        mail_gateway=FakeMailGateway([_submission_message(config)]),
        product_gate=RecordingProductGate(manifest_r_digest=""),
        now_fn=lambda: FIXED_NOW,
    )
    controller.run_once()
    with pytest.raises(Exception, match="manifest_r_digest"):
        controller.create_request(
            event_id="evt-1",
            round_id=2,
            test_result="PASS",
            summary="回归通过",
            output_dir=str(tmp_path / "out"),
        )
