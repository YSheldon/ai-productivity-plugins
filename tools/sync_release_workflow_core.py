from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path


PLUGIN_NAMES = ("test-submission", "submission-gate", "pre-release", "release-gate")


def repo_root_from(script_path: Path) -> Path:
    return script_path.resolve().parents[1]


def canonical_root(repo_root: Path) -> Path:
    return repo_root / "shared" / "release_workflow_core"


def embedded_root(repo_root: Path, plugin_name: str) -> Path:
    return repo_root / "plugins" / plugin_name / "src" / "release_workflow_core"


def canonical_files(source_root: Path) -> list[Path]:
    return sorted(
        path for path in source_root.rglob("*") if path.is_file() and "__pycache__" not in path.parts
    )


def compare_target(
    source_root: Path,
    target_root: Path,
    *,
    allow_missing_targets: bool,
) -> dict[str, object]:
    source_paths = canonical_files(source_root)
    if not target_root.exists():
        if allow_missing_targets:
            return {"status": "skipped", "missing": [str(target_root)]}
        return {"status": "drift", "missing": [str(target_root)]}
    missing: list[str] = []
    changed: list[str] = []
    for source_path in source_paths:
        relative = source_path.relative_to(source_root)
        target_path = target_root / relative
        if not target_path.is_file():
            missing.append(relative.as_posix())
            continue
        if target_path.read_bytes() != source_path.read_bytes():
            changed.append(relative.as_posix())
    status = "clean" if not missing and not changed else "drift"
    return {"status": status, "missing": missing, "changed": changed}


def sync_target(source_root: Path, target_root: Path) -> dict[str, object]:
    source_paths = canonical_files(source_root)
    target_root.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for source_path in source_paths:
        relative = source_path.relative_to(source_root)
        target_path = target_root / relative
        target_path.parent.mkdir(parents=True, exist_ok=True)
        payload = source_path.read_bytes()
        if not target_path.exists() or target_path.read_bytes() != payload:
            target_path.write_bytes(payload)
            written.append(relative.as_posix())
    return {"status": "synced", "written": written}


def build_report(
    repo_root: Path,
    *,
    check_only: bool,
    allow_missing_targets: bool,
) -> dict[str, object]:
    source_root = canonical_root(repo_root)
    if not source_root.is_dir():
        raise SystemExit(f"canonical core directory is missing: {source_root}")
    report: dict[str, object] = {"repo_root": str(repo_root), "source_root": str(source_root), "plugins": {}}
    plugins: dict[str, object] = {}
    for plugin_name in PLUGIN_NAMES:
        target_root = embedded_root(repo_root, plugin_name)
        if check_only:
            plugins[plugin_name] = compare_target(
                source_root, target_root, allow_missing_targets=allow_missing_targets
            )
        else:
            plugins[plugin_name] = sync_target(source_root, target_root)
    report["plugins"] = plugins
    return report


def has_drift(report: dict[str, object]) -> bool:
    plugins = report.get("plugins")
    if not isinstance(plugins, dict):
        return True
    for payload in plugins.values():
        if not isinstance(payload, dict):
            return True
        if payload.get("status") == "drift":
            return True
    return False


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync the canonical release_workflow_core into embedded plugin copies.")
    parser.add_argument("--repo-root", type=Path, default=repo_root_from(Path(__file__)))
    parser.add_argument("--check", action="store_true", help="Verify embedded copies without writing.")
    parser.add_argument(
        "--drift",
        action="store_true",
        help="Print the drift report as JSON and do not write.",
    )
    parser.add_argument(
        "--allow-missing-targets",
        action="store_true",
        help="Skip absent embedded target directories. Intended only for explicit generation fixtures.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    repo_root = args.repo_root.resolve()
    check_only = bool(args.check or args.drift)
    report = build_report(
        repo_root,
        check_only=check_only,
        allow_missing_targets=bool(args.allow_missing_targets),
    )
    if args.drift or args.check:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 1 if has_drift(report) else 0
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
