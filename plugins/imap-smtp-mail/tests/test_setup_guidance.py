from __future__ import annotations

import importlib.util
import json
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "src" / "imap_smtp_mail_mcp.py"
SPEC = importlib.util.spec_from_file_location("imap_smtp_mail_mcp", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_server_version_matches_plugin_manifest() -> None:
    manifest_path = Path(__file__).parents[1] / ".codex-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["version"] == MODULE.SERVER_VERSION == "0.1.1"


def test_tencent_exmail_preset_has_exact_setup_paths() -> None:
    auth_note = MODULE.PROVIDER_PRESETS["tencent-exmail"]["auth_note"]

    assert "设置 > 账户 > 客户端专用密码" in auth_note
    assert "设置 > 客户端设置" in auth_note
    assert "开启 IMAP/SMTP 服务" in auth_note
    assert "不要填写网页登录密码" in auth_note


def test_setup_page_shows_tencent_exmail_guidance() -> None:
    page = MODULE.render_setup_page("test-token", provider="tencent-exmail")

    assert "设置 &gt; 账户 &gt; 客户端专用密码" in page
    assert "设置 &gt; 客户端设置" in page
    assert "开启 IMAP/SMTP 服务" in page
    assert "此处填写客户端专用密码" in page
