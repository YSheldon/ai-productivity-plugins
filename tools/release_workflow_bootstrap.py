from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable


MARKETPLACE_URL = "https://github.com/YSheldon/ai-productivity-plugins.git"
PROFILES: dict[str, tuple[str, ...]] = {
    "release-approval": ("imap-smtp-mail", "rd-flywheel", "lark-cli"),
    "release-approval-verifier": (
        "imap-smtp-mail",
        "rd-flywheel",
        "lark-cli",
        "product-release-gate",
    ),
}
_MARKETPLACE_NAME = "ai-productivity-plugins"
_PROFILE_PATTERN = re.compile(r"^[a-z0-9-]+$")
_LOCK_FILENAME = "dependency-lock.json"

Runner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]


def run_command(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _sha256_directory(path: Path) -> str:
    digest = hashlib.sha256()
    for child in sorted(item for item in path.rglob("*") if item.is_file()):
        relative = child.relative_to(path).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\n")
        digest.update(child.read_bytes())
        digest.update(b"\n")
    return digest.hexdigest()


def _sha256_path(path: Path) -> str:
    if path.is_dir():
        return _sha256_directory(path)
    return _sha256_file(path)


def _repo_root(repo_root: str | Path | None) -> Path:
    if repo_root is None:
        return Path(__file__).resolve().parents[1]
    return Path(repo_root).resolve()


def _resolve_within(base: Path, relative_path: str) -> Path:
    candidate = (base / relative_path).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError as exc:
        raise ValueError(f"Path escapes base directory: {relative_path}") from exc
    return candidate


def _require_profile(profile: str) -> tuple[str, ...]:
    if not _PROFILE_PATTERN.fullmatch(profile):
        raise ValueError(f"Unsupported profile: {profile}")
    plugins = PROFILES.get(profile)
    if plugins is None:
        raise ValueError(f"Unsupported profile: {profile}")
    return plugins


def _load_marketplace(repo_root: Path) -> tuple[str, dict[str, Path]]:
    marketplace_path = repo_root / ".agents" / "plugins" / "marketplace.json"
    marketplace = json.loads(marketplace_path.read_text(encoding="utf-8"))
    name = marketplace.get("name")
    if name != _MARKETPLACE_NAME:
        raise ValueError(f"Unsupported marketplace: {name}")
    plugins: dict[str, Path] = {}
    for entry in marketplace.get("plugins", []):
        if not isinstance(entry, dict):
            continue
        plugin_name = entry.get("name")
        source = entry.get("source")
        if not isinstance(plugin_name, str) or not isinstance(source, dict):
            continue
        if source.get("source") != "local":
            continue
        source_path = source.get("path")
        if not isinstance(source_path, str):
            continue
        plugins[plugin_name] = _resolve_within(repo_root, source_path)
    return name, plugins


def _entrypoint_records(plugin_root: Path, manifest: dict[str, Any]) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    seen: set[str] = set()

    def append(kind: str, path: Path) -> None:
        normalized = path.resolve().as_posix()
        if normalized in seen:
            return
        seen.add(normalized)
        records.append({"kind": kind, "path": normalized, "sha256": _sha256_path(path)})

    skills_path = manifest.get("skills")
    if isinstance(skills_path, str):
        append("skills", _resolve_within(plugin_root, skills_path))

    mcp_path = manifest.get("mcpServers")
    if isinstance(mcp_path, str):
        mcp_config_path = _resolve_within(plugin_root, mcp_path)
        append("mcp_config", mcp_config_path)
        mcp_config = json.loads(mcp_config_path.read_text(encoding="utf-8"))
        for server in mcp_config.get("mcpServers", {}).values():
            if not isinstance(server, dict):
                continue
            for argument in server.get("args", []):
                if isinstance(argument, str) and argument.startswith(("./", ".\\", "../", "..\\")):
                    append("mcp_local_arg", _resolve_within(plugin_root, argument))
    return records


def _plugin_metadata(plugin_name: str, plugin_root: Path) -> dict[str, Any]:
    manifest_path = plugin_root / ".codex-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    version = manifest.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"Missing version for {plugin_name}")
    return {
        "name": plugin_name,
        "version": version,
        "marketplace_plugin_id": f"{plugin_name}@{_MARKETPLACE_NAME}",
        "plugin_root": plugin_root.resolve().as_posix(),
        "manifest_path": manifest_path.resolve().as_posix(),
        "manifest_sha256": _sha256_file(manifest_path),
        "entrypoints": _entrypoint_records(plugin_root, manifest),
    }


def _git_commit(repo_root: Path, runner: Runner) -> str:
    completed = runner(["git", "rev-parse", "HEAD"], repo_root)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "git rev-parse HEAD failed")
    commit = completed.stdout.strip()
    if not commit:
        raise RuntimeError("git rev-parse HEAD returned an empty commit")
    return commit


def _parse_install_payload(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "plugin install failed")
    payload_text = completed.stdout.strip()
    if not payload_text:
        return {}
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"plugin install returned invalid JSON: {payload_text}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("plugin install JSON payload must be an object")
    return payload


def _install_changed(payload: dict[str, Any]) -> bool:
    if payload.get("updated") is True:
        return True
    if payload.get("changed") is True:
        return True
    action = payload.get("action")
    if isinstance(action, str) and action.upper() in {"INSTALL", "INSTALLED", "UPDATE", "UPDATED", "UPGRADE", "UPGRADED"}:
        return True
    status = payload.get("status")
    if isinstance(status, str) and status.upper() in {"INSTALLED", "UPDATED", "UPGRADED"}:
        return True
    return False


def bootstrap_profile(
    profile: str,
    *,
    repo_root: str | Path | None = None,
    runner: Runner = run_command,
    codex_command: str = "codex",
) -> dict[str, Any]:
    plugin_names = _require_profile(profile)
    resolved_repo_root = _repo_root(repo_root)
    marketplace_name, marketplace_paths = _load_marketplace(resolved_repo_root)
    commit = _git_commit(resolved_repo_root, runner)

    fresh_task_required = False
    plugins: list[dict[str, Any]] = []
    for plugin_name in plugin_names:
        plugin_root = marketplace_paths.get(plugin_name)
        if plugin_root is None:
            raise ValueError(f"Plugin missing from marketplace: {plugin_name}")
        plugin_metadata = _plugin_metadata(plugin_name, plugin_root)
        install_command = [codex_command, "plugin", "add", plugin_metadata["marketplace_plugin_id"], "--json"]
        payload = _parse_install_payload(runner(install_command, resolved_repo_root))
        plugin_metadata["install_result"] = payload
        fresh_task_required = fresh_task_required or _install_changed(payload)
        plugins.append(plugin_metadata)

    lock_payload = {
        "profile": profile,
        "marketplace": {
            "name": marketplace_name,
            "url": MARKETPLACE_URL,
            "commit": commit,
        },
        "plugins": plugins,
    }
    lock_path = resolved_repo_root / _LOCK_FILENAME
    lock_path.write_text(json.dumps(lock_payload, indent=2) + "\n", encoding="utf-8")

    return {
        "profile": profile,
        "marketplace": lock_payload["marketplace"],
        "dependency_lock": lock_path.resolve().as_posix(),
        "plugins": plugins,
        "fresh_task_required": fresh_task_required,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install the fixed release workflow plugin profile and freeze dependency metadata.")
    parser.add_argument("profile", choices=sorted(PROFILES), help="Fixed release workflow profile to bootstrap.")
    parser.add_argument("--repo-root", type=Path, help="Override the repository root used for marketplace inspection.")
    parser.add_argument("--codex-command", default="codex", help="Codex executable name or path.")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    result = bootstrap_profile(args.profile, repo_root=args.repo_root, codex_command=args.codex_command)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())