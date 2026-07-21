from __future__ import annotations

import sys
from os import pathsep
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from role_snapshot import (
    CapabilityBlockedError,
    build_lark_fetch_args,
    fetch_role_snapshot,
    parse_role_snapshot_markdown,
    resolve_lark_cli_command,
)


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
        command_prefix=("lark-cli",),
    )

    assert tuple(role.role_id for role in snapshot.roles) == ("release-manager", "security-reviewer")
    assert isinstance(observed["args"], (list, tuple))
    assert observed["args"] == [
        "lark-cli",
        "docs",
        "+fetch",
        "--api-version",
        "v2",
        "--doc",
        "https://open.feishu.cn/docx/release-role-doc",
        "--doc-format",
        "markdown",
        "--as",
        "user",
        "--format",
        "pretty",
    ]
    assert "--scope" not in observed["args"]
    assert observed["kwargs"].get("shell", False) is False
    assert observed["kwargs"]["timeout"] == 30.0


def test_windows_lark_cli_resolves_the_npm_node_entry_without_cmd_shell(tmp_path: Path) -> None:
    npm_root = tmp_path / "npm"
    node_entry = npm_root / "node_modules" / "@larksuite" / "cli" / "scripts" / "run.js"
    node_entry.parent.mkdir(parents=True)
    node_entry.write_text("// test entry\n", encoding="utf-8")
    node_executable = tmp_path / "node.exe"

    def fake_which(name: str) -> str | None:
        if name in {"node.exe", "node"}:
            return str(node_executable)
        return None

    prefix = resolve_lark_cli_command(
        platform_name="nt",
        search_path=pathsep.join((str(tmp_path / "tools"), str(npm_root))),
        which=fake_which,
    )

    assert prefix == (str(node_executable), str(node_entry.resolve()))
    args = build_lark_fetch_args(
        "https://open.feishu.cn/docx/release-role-doc",
        command_prefix=prefix,
    )
    assert args[:5] == [
        str(node_executable),
        str(node_entry.resolve()),
        "docs",
        "+fetch",
        "--api-version",
    ]
    assert "cmd.exe" not in args
    assert "--scope" not in args


def test_disabled_role_may_leave_email_blank_but_is_not_frozen() -> None:
    markdown = """## 审批角色
| role_id | email | required | enabled |
| --- | --- | --- | --- |
| release-manager | release-manager@example.com | true | true |
| client-lead |  | true | false |
"""

    snapshot = parse_role_snapshot_markdown(
        markdown,
        document_url="https://open.feishu.cn/docx/release-role-doc",
        heading="## 审批角色",
    )

    assert tuple(role.role_id for role in snapshot.roles) == ("release-manager",)
    assert snapshot.required_role_ids == ("release-manager",)


@pytest.mark.parametrize(
    ("markdown", "message"),
    [
        (
            """## 审批角色
| role_id | email | required | enabled |
| --- | --- | --- | --- |
| release-manager | first@example.com | true | true |
| release-manager | second@example.com | true | true |
""",
            "duplicate role_id",
        ),
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
        (
            """## 审批角色
| role_id | email | required | enabled |
| --- | --- | --- | --- |
| release-manager | not-an-email | true | true |
""",
            "valid email address",
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