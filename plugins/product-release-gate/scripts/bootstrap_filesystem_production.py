from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path
from typing import Any, Mapping


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from filesystem_release_adapter import ADAPTER_VERSION, durable_replace
from release_gate_core import GateError, deep_merge, default_config
from release_gate_production import ProductionReleaseController
from release_gate_credentials import (
    DEFAULT_AUDIT_CREDENTIAL_TARGET,
    DEFAULT_AUTHORIZATION_CREDENTIAL_TARGET,
)


ADAPTER_FILENAME = "filesystem_release_adapter.py"
LOCK_FILENAME = "deployment-adapter.lock.json"
REQUIRED_STAGES = (
    "preproduction",
    "production_canary",
    "production_full",
)
_ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SENSITIVE_KEY_SUFFIXES = (
    "password",
    "secret",
    "token",
    "api_key",
    "access_key",
    "private_key",
)
_DEPLOYMENT_CHECKS = frozenset(
    {
        "deployment_stages",
        "deployment.targets",
        "deployment.deploy_command",
        "deployment.verify_command",
        "deployment.rollback_command",
        "deployment.rollback_verify_command",
        "deployment.adapter_lock",
        "readback.command",
    }
)


class BootstrapError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _write_new_file(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    try:
        _reject_redirected_path(path.parent, "managed output parent")
        _write_new_file(temporary, payload)
        durable_replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _paths_overlap(left: Path, right: Path) -> bool:
    return _is_relative_to(left, right) or _is_relative_to(right, left)


def _normalize_path(value: str | Path, *, require_absolute: bool) -> Path:
    candidate = Path(os.path.expandvars(str(value))).expanduser()
    if require_absolute and not candidate.is_absolute():
        raise BootstrapError("path must be absolute")
    return Path(os.path.abspath(os.path.normpath(os.fspath(candidate))))


def _reject_redirected_path(path: Path, label: str) -> None:
    current = path
    while True:
        try:
            metadata = current.stat(follow_symlinks=False)
        except FileNotFoundError:
            metadata = None
        except OSError as exc:
            raise BootstrapError(f"{label} cannot be resolved safely") from exc
        if metadata is not None:
            file_attributes = getattr(metadata, "st_file_attributes", 0)
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if stat.S_ISLNK(metadata.st_mode) or file_attributes & reparse_flag:
                raise BootstrapError(
                    f"{label} cannot be a symlink or redirected path"
                )
        parent = current.parent
        if parent == current:
            break
        current = parent


def _resolve_target(value: str | Path, label: str) -> Path:
    try:
        normalized = _normalize_path(value, require_absolute=True)
    except BootstrapError as exc:
        raise BootstrapError(f"{label} must be an absolute path") from exc
    if normalized == Path(normalized.anchor):
        raise BootstrapError(f"{label} cannot be a filesystem root")
    _reject_redirected_path(normalized, label)
    try:
        return normalized.resolve(strict=False)
    except OSError as exc:
        raise BootstrapError(f"{label} cannot be resolved safely") from exc


def _resolve_output(value: str | Path, label: str) -> Path:
    normalized = _normalize_path(value, require_absolute=False)
    if normalized == Path(normalized.anchor):
        raise BootstrapError(f"{label} cannot be a filesystem root")
    _reject_redirected_path(normalized, label)
    try:
        return normalized.resolve(strict=False)
    except OSError as exc:
        raise BootstrapError(f"{label} cannot be resolved safely") from exc


def _embedded_secret_paths(
    value: Any,
    *,
    prefix: str = "",
) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for raw_key, child in value.items():
            key = str(raw_key)
            normalized = key.casefold().replace("-", "_")
            path = f"{prefix}.{key}" if prefix else key
            sensitive = (
                not normalized.endswith("_env")
                and any(
                    normalized == suffix
                    or normalized.endswith(f"_{suffix}")
                    for suffix in _SENSITIVE_KEY_SUFFIXES
                )
            )
            if sensitive and child not in (None, "", [], {}):
                found.append(path)
            found.extend(_embedded_secret_paths(child, prefix=path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(
                _embedded_secret_paths(
                    child,
                    prefix=f"{prefix}[{index}]",
                )
            )
    return found


def _load_base_config(source_config: Path | None) -> dict[str, Any]:
    if source_config is None:
        return default_config()
    try:
        raw = json.loads(source_config.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BootstrapError("source configuration is missing") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise BootstrapError(
            "source configuration is unreadable or invalid JSON"
        ) from exc
    if not isinstance(raw, dict):
        raise BootstrapError("source configuration must be one JSON object")
    secrets = _embedded_secret_paths(raw)
    if secrets:
        raise BootstrapError(
            "source configuration embeds secret values: " + ", ".join(secrets)
        )
    return deep_merge(default_config(), raw)


def _validate_env_name(value: str, label: str) -> str:
    name = str(value or "").strip()
    if not _ENV_NAME_PATTERN.fullmatch(name):
        raise BootstrapError(f"{label} is not a valid environment variable name")
    return name


def _command_templates(
    python_path: Path,
    adapter_path: Path,
    authorization_key_env: str,
) -> dict[str, list[str]]:
    prefix = [str(python_path), str(adapter_path)]
    return {
        "deploy": [
            *prefix,
            "deploy",
            "--stage",
            "{stage}",
            "--target",
            "{target_ref}",
            "--manifest-r",
            "{manifest_r_path}",
            "--authorization",
            "{authorization_path}",
            "--idempotency-key",
            "{idempotency_key}",
            "--expected-digest",
            "{manifest_r_digest}",
            "--authorization-key-env",
            authorization_key_env,
            "--json",
        ],
        "verify": [
            *prefix,
            "verify",
            "--stage",
            "{stage}",
            "--target",
            "{target_ref}",
            "--deployment-ref",
            "{deployment_ref}",
            "--rollback-ref",
            "{rollback_ref}",
            "--expected-digest",
            "{manifest_r_digest}",
            "--json",
        ],
        "rollback": [
            *prefix,
            "rollback",
            "--stage",
            "{stage}",
            "--target",
            "{target_ref}",
            "--deployment-ref",
            "{deployment_ref}",
            "--rollback-ref",
            "{rollback_ref}",
            "--json",
        ],
        "rollback_verify": [
            *prefix,
            "verify-rollback",
            "--stage",
            "{stage}",
            "--target",
            "{target_ref}",
            "--deployment-ref",
            "{deployment_ref}",
            "--rollback-ref",
            "{rollback_ref}",
            "--restored-ref",
            "{restored_ref}",
            "--rollback-receipt-ref",
            "{rollback_receipt_ref}",
            "--json",
        ],
        "readback": [
            *prefix,
            "readback",
            "--target",
            "{target_ref}",
            "--expected-digest",
            "{manifest_r_digest}",
            "--json",
        ],
    }


def _dependency_lock(
    commands: Mapping[str, list[str]],
    *,
    python_path: Path,
    adapter_path: Path,
) -> dict[str, Any]:
    entrypoints = [
        {
            "argv_index": 0,
            "path": str(python_path),
            "sha256": sha256_file(python_path),
        },
        {
            "argv_index": 1,
            "path": adapter_path.name,
            "sha256": sha256_file(adapter_path),
        },
    ]
    return {
        "schema_version": 1,
        "adapter": "filesystem-release-adapter",
        "adapter_version": ADAPTER_VERSION,
        "root": ".",
        "commands": {
            command_id: {
                "argv_template": command,
                "entrypoints": entrypoints,
            }
            for command_id, command in commands.items()
        },
    }


def _build_config(
    base: dict[str, Any],
    *,
    targets: Mapping[str, Path],
    lock_path: Path,
    lock_digest: str,
    commands: Mapping[str, list[str]],
    authorization_key_env: str,
    audit_key_env: str,
) -> dict[str, Any]:
    config = deep_merge({}, base)
    runtime = config.setdefault("runtime", {})
    runtime.update(
        {
            "auto_authorize_verified_pre_release": False,
            "auto_deploy_authorized_releases": False,
            "auto_generate_production_report": False,
            "auto_deliver_production_report": False,
        }
    )
    identity_binding = runtime.setdefault("identity_binding", {})
    if not isinstance(identity_binding, dict):
        raise BootstrapError(
            "runtime.identity_binding configuration must be an object"
        )
    identity_binding["required"] = True
    identity_binding["principal_sha256"] = str(
        identity_binding.get("principal_sha256") or ""
    ).strip().lower()
    production = config.setdefault("production", {})
    production["enabled"] = False
    authorization = production.setdefault("authorization", {})
    authorization["key_env"] = authorization_key_env
    authorization.setdefault(
        "credential_target",
        DEFAULT_AUTHORIZATION_CREDENTIAL_TARGET,
    )
    authorization.setdefault("ttl_seconds", 3600)
    audit = production.setdefault("audit", {})
    audit["key_env"] = audit_key_env
    audit.setdefault(
        "credential_target",
        DEFAULT_AUDIT_CREDENTIAL_TARGET,
    )
    deployment = production.setdefault("deployment", {})
    deployment.update(
        {
            "stages": list(REQUIRED_STAGES),
            "targets": {
                stage: str(targets[stage]) for stage in REQUIRED_STAGES
            },
            "dependency_lock": str(lock_path),
            "dependency_lock_sha256": lock_digest,
            "deploy_command": commands["deploy"],
            "verify_command": commands["verify"],
            "rollback_command": commands["rollback"],
            "rollback_verify_command": commands["rollback_verify"],
            "timeout_seconds": int(deployment.get("timeout_seconds") or 900),
        }
    )
    readback = production.setdefault("readback", {})
    readback.update(
        {
            "command": commands["readback"],
            "timeout_seconds": int(readback.get("timeout_seconds") or 180),
        }
    )
    report_delivery = production.setdefault("report_delivery", {})
    report_delivery["enabled"] = False
    return config


def _validate_locations(
    *,
    targets: Mapping[str, Path],
    adapter_dir: Path,
    output_config: Path,
) -> None:
    values = list(targets.items())
    for index, (left_name, left) in enumerate(values):
        if _paths_overlap(adapter_dir, left):
            raise BootstrapError(
                f"adapter directory overlaps {left_name} target"
            )
        if _is_relative_to(output_config, left):
            raise BootstrapError(
                f"output configuration is inside {left_name} target"
            )
        for right_name, right in values[index + 1 :]:
            if _paths_overlap(left, right):
                raise BootstrapError(
                    f"{left_name} and {right_name} targets overlap"
                )
    if _paths_overlap(adapter_dir, PLUGIN_ROOT.resolve()):
        raise BootstrapError(
            "adapter directory must be outside the mutable plugin directory"
        )


def _prepare_adapter_directory(
    adapter_dir: Path, replace: bool
) -> bool:
    allowed_names = {ADAPTER_FILENAME, LOCK_FILENAME}
    _reject_redirected_path(adapter_dir, "adapter directory")
    if adapter_dir.exists():
        if not adapter_dir.is_dir():
            raise BootstrapError("adapter directory path is not a directory")
        if not replace:
            raise BootstrapError(
                "adapter directory already exists; use --replace explicitly"
            )
        unexpected = sorted(
            child.name
            for child in adapter_dir.iterdir()
            if child.name not in allowed_names
        )
        if unexpected:
            raise BootstrapError(
                "adapter directory contains unmanaged entries: "
                + ", ".join(unexpected)
            )
        return False
    adapter_dir.mkdir(parents=True)
    _reject_redirected_path(adapter_dir, "adapter directory")
    return True


def _install_immutable_file(
    path: Path,
    payload: bytes,
    *,
    created_files: list[Path],
) -> None:
    if path.exists():
        if not path.is_file() or path.is_symlink():
            raise BootstrapError(f"managed adapter path is unsafe: {path.name}")
        if path.read_bytes() != payload:
            raise BootstrapError(
                f"immutable adapter file differs: {path.name}; "
                "choose a new --adapter-dir for the upgrade"
            )
        return
    atomic_write(path, payload)
    created_files.append(path)


def _cleanup_adapter_install(
    adapter_dir: Path,
    *,
    created_files: list[Path],
    created_directory: bool,
) -> None:
    for path in reversed(created_files):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    if created_directory:
        try:
            adapter_dir.rmdir()
        except OSError:
            pass


def bootstrap_filesystem_production(
    *,
    output_config: str | Path,
    preproduction_target: str | Path,
    canary_target: str | Path,
    production_target: str | Path,
    adapter_dir: str | Path | None = None,
    source_config: str | Path | None = None,
    authorization_key_env: str = "PRODUCT_RELEASE_GATE_AUTH_KEY",
    audit_key_env: str = "PRODUCT_RELEASE_GATE_AUDIT_KEY",
    replace: bool = False,
) -> dict[str, Any]:
    output_path = _resolve_output(output_config, "output configuration")
    resolved_adapter_dir = (
        _resolve_output(adapter_dir, "adapter directory")
        if adapter_dir is not None
        else _resolve_output(
            output_path.parent
            / "adapters"
            / f"filesystem-release-adapter-{ADAPTER_VERSION}",
            "adapter directory",
        )
    )
    targets = {
        "preproduction": _resolve_target(
            preproduction_target,
            "preproduction target",
        ),
        "production_canary": _resolve_target(
            canary_target,
            "production canary target",
        ),
        "production_full": _resolve_target(
            production_target,
            "production full target",
        ),
    }
    auth_env = _validate_env_name(
        authorization_key_env,
        "authorization key environment variable",
    )
    audit_env = _validate_env_name(
        audit_key_env,
        "audit key environment variable",
    )
    if auth_env == audit_env:
        raise BootstrapError(
            "authorization and audit keys must use different environment variables"
        )
    _validate_locations(
        targets=targets,
        adapter_dir=resolved_adapter_dir,
        output_config=output_path,
    )
    if output_path.exists() and not replace:
        raise BootstrapError(
            "output configuration already exists; use --replace explicitly"
        )
    source_path = (
        _resolve_output(
            source_config,
            "source configuration",
        )
        if source_config is not None
        else None
    )
    base_config = _load_base_config(source_path)
    created_directory = _prepare_adapter_directory(
        resolved_adapter_dir,
        replace,
    )
    created_files: list[Path] = []
    try:
        source_adapter = PLUGIN_ROOT / "src" / ADAPTER_FILENAME
        if source_adapter.is_symlink() or not source_adapter.is_file():
            raise BootstrapError("packaged filesystem release adapter is missing")
        adapter_path = resolved_adapter_dir / ADAPTER_FILENAME
        _install_immutable_file(
            adapter_path,
            source_adapter.read_bytes(),
            created_files=created_files,
        )
        python_path = Path(sys.executable).resolve(strict=True)
        commands = _command_templates(python_path, adapter_path, auth_env)
        lock_path = resolved_adapter_dir / LOCK_FILENAME
        lock_payload = _dependency_lock(
            commands,
            python_path=python_path,
            adapter_path=adapter_path,
        )
        lock_bytes = (json.dumps(lock_payload, indent=2) + "\n").encode(
            "utf-8"
        )
        _install_immutable_file(
            lock_path,
            lock_bytes,
            created_files=created_files,
        )
        lock_digest = sha256_file(lock_path)
        config = _build_config(
            base_config,
            targets=targets,
            lock_path=lock_path.resolve(),
            lock_digest=lock_digest,
            commands=commands,
            authorization_key_env=auth_env,
            audit_key_env=audit_env,
        )
        validation_config = deep_merge({}, config)
        validation_config["production"]["enabled"] = True
        candidate = output_path.parent / (
            f".{output_path.name}.{uuid.uuid4().hex}.candidate"
        )
        try:
            _write_new_file(
                candidate,
                (json.dumps(validation_config, indent=2) + "\n").encode(
                    "utf-8"
                ),
            )
            try:
                controller = ProductionReleaseController(str(candidate))
                production_preflight = controller.production_preflight(
                    include_report_delivery=False
                )
            except GateError as exc:
                raise BootstrapError(
                    f"generated production configuration is invalid: {exc}"
                ) from exc
            checks = {
                str(check.get("name")): bool(check.get("configured"))
                for check in production_preflight.get("checks", [])
            }
            failed_deployment_checks = sorted(
                name
                for name in _DEPLOYMENT_CHECKS
                if checks.get(name) is not True
            )
            if failed_deployment_checks:
                raise BootstrapError(
                    "generated deployment configuration failed self-check: "
                    + ", ".join(failed_deployment_checks)
                )
            atomic_write(
                candidate,
                (json.dumps(config, indent=2) + "\n").encode("utf-8"),
            )
            durable_replace(candidate, output_path)
        finally:
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass
    except Exception:
        _cleanup_adapter_install(
            resolved_adapter_dir,
            created_files=created_files,
            created_directory=created_directory,
        )
        raise

    core_preflight = ProductionReleaseController(str(output_path)).preflight()
    external_requirements = [
        name
        for name in production_preflight.get("missing_capabilities", [])
        if name not in _DEPLOYMENT_CHECKS
    ]
    return {
        "result": "PASS",
        "production_enabled": False,
        "automatic_actions_enabled": False,
        "secrets_written": False,
        "config_path": str(output_path),
        "adapter": {
            "path": str(adapter_path),
            "version": ADAPTER_VERSION,
            "sha256": sha256_file(adapter_path),
        },
        "dependency_lock": {
            "path": str(lock_path),
            "sha256": lock_digest,
        },
        "targets": {stage: str(targets[stage]) for stage in REQUIRED_STAGES},
        "deployment_binding_ready": True,
        "external_requirements": external_requirements,
        "core_missing_integrations": core_preflight.get(
            "missing_required_integrations",
            [],
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Install and lock the built-in filesystem production adapter. "
            "The generated configuration stays fail-closed and disabled."
        )
    )
    parser.add_argument(
        "--output-config",
        type=Path,
        default=(
            Path.home()
            / ".codex"
            / "product-release-gate"
            / "config.json"
        ),
    )
    parser.add_argument("--preproduction-target", required=True)
    parser.add_argument("--canary-target", required=True)
    parser.add_argument("--production-target", required=True)
    parser.add_argument("--adapter-dir", type=Path)
    parser.add_argument("--source-config", type=Path)
    parser.add_argument(
        "--authorization-key-env",
        default="PRODUCT_RELEASE_GATE_AUTH_KEY",
    )
    parser.add_argument(
        "--audit-key-env",
        default="PRODUCT_RELEASE_GATE_AUDIT_KEY",
    )
    parser.add_argument("--replace", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = bootstrap_filesystem_production(
            output_config=args.output_config,
            preproduction_target=args.preproduction_target,
            canary_target=args.canary_target,
            production_target=args.production_target,
            adapter_dir=args.adapter_dir,
            source_config=args.source_config,
            authorization_key_env=args.authorization_key_env,
            audit_key_env=args.audit_key_env,
            replace=args.replace,
        )
    except (BootstrapError, GateError, OSError, ValueError) as exc:
        result = {
            "result": "FAIL",
            "error_code": "FILESYSTEM_PRODUCTION_BOOTSTRAP_BLOCKED",
            "error": str(exc),
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
