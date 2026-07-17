from __future__ import annotations

import sys
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from role_snapshot import CapabilityBlockedError, parse_role_snapshot_markdown, fetch_role_snapshot


FIXTURE_ROOT = PLUGIN_ROOT / "tests" / "fixtures"


def test_parse_role_snapshot_scopes_to_the_requested_heading_and_hashes_sorted_roles() -> None:
    markdown = (FIXTURE_ROOT / "role-document.md").read_text(encoding="utf-8")

    snapshot = parse_role_snapshot_markdown(
        markdown,
        document_url="https://open.feishu.cn/docx/release-role-doc",
        heading="## 审批角色",
    )

    assert tuple(role.role_id for role in snapshot.roles) == ("release-manager", "security-reviewer")
    assert tuple(role.email for role in snapshot.roles) == (
        "release-manager@example.com",
        "security-reviewer@example.com",
    )
    assert snapshot.required_role_ids == ("release-manager",)
    assert snapshot.digest.startswith("sha256:")
    assert len(snapshot.digest) == 71


def test_fetch_role_snapshot_uses_lark_cli_argument_arrays() -> None:
    markdown = (FIXTURE_ROOT / "role-document.md").read_text(encoding="utf-8")
    observed: dict[str, object] = {}

    def fake_runner(args, **kwargs):
        observed["args"] = args
        observed["kwargs"] = kwargs
        return CompletedProcess(args, 0, stdout=markdown, stderr="")

    snapshot = fetch_role_snapshot(
        "https://open.feishu.cn/docx/release-role-doc",
        heading="## 审批角色",
        runner=fake_runner,
    )

    assert tuple(role.role_id for role in snapshot.roles) == ("release-manager", "security-reviewer")
    assert isinstance(observed["args"], (list, tuple))
    assert observed["args"][:3] == ["lark-cli", "docs", "+fetch"]
    assert observed["kwargs"].get("shell", False) is False
    assert observed["kwargs"]["timeout"] == 30.0


@pytest.mark.parametrize(
    ("markdown", "message"),
    [
        (
            """## 审批角色
| role_id | email | required | enabled |
| --- | --- | --- | --- |
| release-manager | same@example.com | true | true |
| security-reviewer | same@example.com | false | true |
""",
            "duplicate email",
        ),
        (
            """## 审批角色
| role_id | email | required | enabled |
| --- | --- | --- | --- |
| release-manager | release-manager@example.com | false | true |
""",
            "required role",
        ),
        (
            """## 审批角色
not a table
""",
            "Markdown table",
        ),
    ],
)
def test_role_snapshot_blocks_on_malformed_or_unsafe_role_sections(markdown: str, message: str) -> None:
    with pytest.raises(CapabilityBlockedError, match=message):
        parse_role_snapshot_markdown(
            markdown,
            document_url="https://open.feishu.cn/docx/release-role-doc",
            heading="## 审批角色",
        )


def test_fetch_failure_is_capability_blocked() -> None:
    def fake_runner(args, **kwargs):
        return CompletedProcess(args, 7, stdout="", stderr="docs fetch failed")

    with pytest.raises(CapabilityBlockedError, match="CAPABILITY_BLOCKED"):
        fetch_role_snapshot(
            "https://open.feishu.cn/docx/release-role-doc",
            heading="## 审批角色",
            runner=fake_runner,
        )


@pytest.mark.parametrize(
    "failure",
    [OSError("lark-cli not found"), TimeoutExpired(["lark-cli"], 30)],
)
def test_fetch_process_failure_or_timeout_is_capability_blocked(
    failure: BaseException,
) -> None:
    def fake_runner(args, **kwargs):
        raise failure

    with pytest.raises(CapabilityBlockedError, match="CAPABILITY_BLOCKED"):
        fetch_role_snapshot(
            "https://open.feishu.cn/docx/release-role-doc",
            heading="## 审批角色",
            runner=fake_runner,
        )