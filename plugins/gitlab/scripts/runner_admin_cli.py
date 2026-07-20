from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = PLUGIN_ROOT / "src" / "gitlab_mcp.py"


def _load_server() -> Any:
    spec = importlib.util.spec_from_file_location("gitlab_runner_admin_cli_server", SERVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("GitLab plugin server could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _is_windows_administrator() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes

        return int(ctypes.windll.shell32.IsUserAnAdmin()) == 1
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _parse_result(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise RuntimeError("GitLab Runner tool returned an invalid result")
    content = result.get("content")
    if not isinstance(content, list) or len(content) != 1 or not isinstance(content[0], dict):
        raise RuntimeError("GitLab Runner tool returned an invalid result")
    text = content[0].get("text")
    if not isinstance(text, str):
        raise RuntimeError("GitLab Runner tool returned an invalid result")
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise RuntimeError("GitLab Runner tool returned an invalid result")
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Provision or resume a policy-bound dedicated Windows GitLab Runner."
    )
    parser.add_argument("action", choices=("provision", "resume"))
    parser.add_argument("--policy-name", required=True)
    parser.add_argument("--profile")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not _is_windows_administrator():
        print(
            "GitLab Runner administration requires an elevated Windows process.",
            file=sys.stderr,
        )
        return 2

    server = _load_server()
    handler = (
        server.provision_windows_project_runner
        if args.action == "provision"
        else server.resume_windows_project_runner
    )
    tool_args = {"policy_name": args.policy_name}
    if args.profile:
        tool_args["profile"] = args.profile
    try:
        payload = _parse_result(handler(tool_args))
    except Exception as exc:  # noqa: BLE001
        sanitizer = getattr(server, "sanitize_error_text", None)
        message = sanitizer(str(exc)) if callable(sanitizer) else "operation failed closed"
        print(f"GitLab Runner administration failed: {message}", file=sys.stderr)
        return 2

    print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
    return 0 if payload.get("ready") is True else 3


if __name__ == "__main__":
    raise SystemExit(main())
