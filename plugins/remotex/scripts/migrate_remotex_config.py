from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE_DIRECTORY))

import config_store  # noqa: E402
import credential_store  # noqa: E402
import remotex_core as core  # noqa: E402
import secure_paths  # noqa: E402


def _parse(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Preview or explicitly migrate a RemoteX v1 config to v2 aliases."
    )
    parser.add_argument("--config", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    return parser.parse_args(argv)


def _read(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise core.ToolError("RemoteX migration config must be a regular local file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise core.ToolError("RemoteX migration config is invalid") from exc
    if not isinstance(value, dict):
        raise core.ToolError("RemoteX migration config is invalid")
    return value


def _backup_path(path: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return path.with_name(
        f"{path.name}.v1-backup-{timestamp}-{uuid.uuid4().hex[:8]}.json"
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse(argv)
    path = Path(args.config).expanduser().resolve(strict=True)
    source = _read(path)
    candidate = credential_store.migrate_v1_config(source)
    if args.check:
        print(
            json.dumps(
                {
                    "status": "preview",
                    "sourceVersion": 1,
                    "credentialAliasCount": len(candidate["credentials"]),
                    "profileCount": len(candidate["profiles"]),
                    "candidate": candidate,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        return 0
    if not args.confirm:
        raise core.ToolError("--confirm is required with --write")

    original = path.read_bytes()
    candidate_bytes = config_store._serialized(candidate)
    backup = _backup_path(path)
    secure_paths.ensure_private_directory(path.parent)
    backup.write_bytes(original)
    secure_paths.ensure_private_file(backup)
    try:
        config_store._atomic_write(path, candidate_bytes)
        readback = core._validate_config(_read(path))
        if readback != candidate:
            raise core.ToolError("RemoteX migration semantic readback differs")
    except Exception as exc:
        try:
            config_store._atomic_write(path, original)
        except Exception as restore_exc:
            raise core.ToolError(
                "RemoteX migration failed and rollback could not be verified"
            ) from restore_exc
        if isinstance(exc, core.ToolError):
            raise
        raise core.ToolError("RemoteX migration failed and was rolled back") from exc

    print(
        json.dumps(
            {
                "status": "written",
                "sourceVersion": 1,
                "targetVersion": 2,
                "credentialAliasCount": len(candidate["credentials"]),
                "profileCount": len(candidate["profiles"]),
                "backupFileName": backup.name,
                "configSha256": hashlib.sha256(candidate_bytes).hexdigest(),
                "backupSha256": hashlib.sha256(original).hexdigest(),
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except core.ToolError as exc:
        print(
            json.dumps(
                {"status": "failed", "error": core.redact_text(str(exc))},
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        raise SystemExit(1)
