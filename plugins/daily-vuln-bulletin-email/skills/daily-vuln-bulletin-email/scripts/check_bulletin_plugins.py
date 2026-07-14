#!/usr/bin/env python3
"""Read-only preflight for plugins required by a daily vulnerability bulletin."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def default_codex_command() -> str:
    # PowerShell often resolves `codex` to a .ps1 shim, which subprocess cannot run.
    if sys.platform == "win32":
        cmd_shim = shutil.which("codex.cmd")
        if cmd_shim:
            return cmd_shim
    return shutil.which("codex") or "codex"

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check required Codex plugin IDs without changing plugin state."
    )
    parser.add_argument(
        "--require",
        action="append",
        required=True,
        metavar="PLUGIN@MARKETPLACE",
        help="Required plugin ID. Repeat for each selected delivery capability.",
    )
    parser.add_argument(
        "--codex",
        default=default_codex_command(),
        help="Codex executable to query (default: a Windows .cmd shim when available).",
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        help="Use a saved `codex plugin list --available --json` response instead of running Codex.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        help="Write the JSON verdict to this path as well as stdout.",
    )
    return parser.parse_args()


def load_inventory(args: argparse.Namespace) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if args.inventory:
        try:
            return json.loads(args.inventory.read_text(encoding="utf-8")), None
        except (OSError, json.JSONDecodeError) as exc:
            return None, {"code": "inventory_read_failed", "message": str(exc)}

    command = [args.codex, "plugin", "list", "--available", "--json"]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        return None, {"code": "plugin_query_unavailable", "message": str(exc), "command": command}

    if completed.returncode != 0:
        return None, {
            "code": "plugin_query_failed",
            "message": completed.stderr.strip() or completed.stdout.strip(),
            "command": command,
            "exitCode": completed.returncode,
        }

    try:
        return json.loads(completed.stdout), None
    except json.JSONDecodeError as exc:
        return None, {
            "code": "plugin_inventory_invalid_json",
            "message": str(exc),
            "command": command,
        }


def index_plugins(inventory: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if isinstance(inventory, list):
        entries: list[Any] = inventory
    elif isinstance(inventory, dict):
        entries = []
        for key in ("installed", "available"):
            value = inventory.get(key, [])
            if isinstance(value, list):
                entries.extend(value)
    else:
        return {}

    indexed: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        plugin_id = entry.get("pluginId")
        if not isinstance(plugin_id, str) or not plugin_id:
            continue
        current = indexed.get(plugin_id)
        if current is None or (entry.get("installed") and not current.get("installed")):
            indexed[plugin_id] = entry
    return indexed


def unique_requirements(requirements: list[str]) -> list[str]:
    result: list[str] = []
    for plugin_id in requirements:
        normalized = plugin_id.strip()
        if normalized and normalized not in result:
            result.append(normalized)
    return result


def assess_plugin(plugin_id: str, entry: dict[str, Any] | None, codex: str) -> dict[str, Any]:
    base: dict[str, Any] = {
        "pluginId": plugin_id,
        "installed": False,
        "enabled": False,
        "installPolicy": None,
        "authPolicy": None,
        "state": "unavailable",
        "installCommand": None,
    }
    if entry is None:
        return base

    base.update(
        {
            "installed": bool(entry.get("installed")),
            "enabled": bool(entry.get("enabled")),
            "installPolicy": entry.get("installPolicy"),
            "authPolicy": entry.get("authPolicy"),
        }
    )
    if base["installed"] and base["enabled"]:
        base["state"] = "ready"
    elif base["installed"]:
        # `codex plugin add` does not document an enable-only mode. Do not guess.
        base["state"] = "disabled"
    elif base["installPolicy"] == "AVAILABLE":
        base["state"] = "installable"
        base["installCommand"] = [codex, "plugin", "add", plugin_id, "--json"]
    return base


def build_verdict(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    requirements = unique_requirements(args.require)
    inventory, error = load_inventory(args)
    generated_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if error:
        return (
            {
                "generatedAt": generated_at,
                "status": "blocked",
                "ready": False,
                "needsUserConsent": False,
                "requirements": [{"pluginId": plugin_id, "state": "unknown"} for plugin_id in requirements],
                "error": error,
            },
            3,
        )

    plugins = index_plugins(inventory or {})
    assessments = [assess_plugin(plugin_id, plugins.get(plugin_id), args.codex) for plugin_id in requirements]
    states = {entry["state"] for entry in assessments}
    if states == {"ready"}:
        status, exit_code = "ready", 0
    elif states.issubset({"ready", "installable"}):
        status, exit_code = "consent_required", 2
    else:
        status, exit_code = "blocked", 3

    return (
        {
            "generatedAt": generated_at,
            "status": status,
            "ready": status == "ready",
            "needsUserConsent": status == "consent_required",
            "requirements": assessments,
            "installablePluginIds": [entry["pluginId"] for entry in assessments if entry["state"] == "installable"],
            "blockedPluginIds": [entry["pluginId"] for entry in assessments if entry["state"] in {"disabled", "unavailable"}],
        },
        exit_code,
    )


def main() -> int:
    args = parse_args()
    verdict, exit_code = build_verdict(args)
    serialized = json.dumps(verdict, ensure_ascii=False, indent=2) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(serialized, encoding="utf-8")
    sys.stdout.write(serialized)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
