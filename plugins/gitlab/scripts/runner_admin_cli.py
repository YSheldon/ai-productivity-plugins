from __future__ import annotations

import argparse
import getpass
import importlib.util
import json
import os
import re
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = PLUGIN_ROOT / "src" / "gitlab_mcp.py"
CREDENTIALS_PATH = PLUGIN_ROOT / "src" / "runner_manager_credentials.py"
_ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _load_server() -> Any:
    spec = importlib.util.spec_from_file_location("gitlab_runner_admin_cli_server", SERVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("GitLab plugin server could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_credentials() -> Any:
    spec = importlib.util.spec_from_file_location(
        "gitlab_runner_manager_credentials",
        CREDENTIALS_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("GitLab Runner credential support could not be loaded")
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


@contextmanager
def _temporary_environment(values: dict[str, str]) -> Iterator[None]:
    previous = {key: os.environ.get(key) for key in values}
    try:
        os.environ.update(values)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _credential_target(credentials: Any, policy_name: str) -> str:
    return str(credentials.credential_target(policy_name))


def _credential_status(args: argparse.Namespace, credentials: Any) -> dict[str, Any]:
    target = _credential_target(credentials, args.policy_name)
    store = credentials.WindowsCredentialStore()
    if args.action == "token-status":
        return {
            "action": "token-status",
            "credential_target": target,
            "token_present": bool(store.read(target)),
            "token_value_returned": False,
        }
    if args.action == "token-clear":
        if not args.confirm_clear:
            raise RuntimeError("token-clear requires --confirm-clear")
        return {
            "action": "token-clear",
            "credential_target": target,
            "token_removed": bool(store.delete(target)),
            "token_value_returned": False,
        }
    if args.action != "token-set":
        raise RuntimeError("Unsupported GitLab Runner credential action")
    existing_present = bool(store.read(target))
    if existing_present and not args.replace_token:
        raise RuntimeError("A Runner manager credential already exists; use --replace-token to replace it")
    if args.token_env:
        if not _ENV_NAME_PATTERN.fullmatch(args.token_env):
            raise RuntimeError("--token-env must name a valid environment variable")
        token = os.environ.get(args.token_env, "")
        if not token:
            raise RuntimeError("The requested --token-env value is not set")
    else:
        try:
            token = getpass.getpass("GitLab Runner manager token (input hidden): ")
        except (EOFError, KeyboardInterrupt) as exc:
            raise RuntimeError("GitLab Runner manager token input was cancelled") from exc
    try:
        store.write(target, credentials.validate_token(token))
    finally:
        token = ""
    return {
        "action": "token-set",
        "credential_target": target,
        "token_present": True,
        "token_value_returned": False,
        "replaced": existing_present,
    }


def _uses_default_environment_profile(args: argparse.Namespace) -> bool:
    return not (
        args.profile
        or os.environ.get("GITLAB_CONFIG")
        or os.environ.get("GITLAB_PROFILE")
        or os.environ.get("GITLAB_TOKEN_ENV")
    )


def _sanitize_lifecycle_error(server: Any, error: Exception, token: str) -> str:
    sanitizer = getattr(server, "sanitize_error_text", None)
    if callable(sanitizer):
        try:
            return str(sanitizer(str(error), secrets=(token,)))
        except TypeError:
            return str(sanitizer(str(error)))
    return "GitLab Runner lifecycle failed closed"


def _run_lifecycle(args: argparse.Namespace, server: Any, credentials: Any) -> dict[str, Any]:
    handler = (
        server.provision_windows_project_runner
        if args.action == "provision"
        else server.resume_windows_project_runner
    )
    tool_args = {"policy_name": args.policy_name}
    if args.profile:
        tool_args["profile"] = args.profile

    if os.environ.get("GITLAB_TOKEN") or not _uses_default_environment_profile(args):
        return _parse_result(handler(tool_args))

    target = _credential_target(credentials, args.policy_name)
    store = credentials.WindowsCredentialStore()
    token = store.read(target)
    if not token:
        raise RuntimeError(
            "GitLab Runner manager credential is missing; run token-set for the same policy_name first"
        )
    try:
        policy = server.load_windows_runner_policy(
            args.policy_name,
            allow_existing_registration=args.action == "resume",
        )
        environment = {"GITLAB_TOKEN": token}
        if not os.environ.get("GITLAB_URL"):
            environment["GITLAB_URL"] = str(policy["gitlab_url"])
        with _temporary_environment(environment):
            payload = _parse_result(handler(tool_args))
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(_sanitize_lifecycle_error(server, exc, token)) from None
    finally:
        token = ""

    credential = {
        "source": "windows_credential_manager",
        "credential_target": target,
        "token_value_returned": False,
    }
    if payload.get("ready") is not True:
        credential["status"] = "retained_for_resume"
        payload["runner_manager_credential"] = credential
        return payload
    try:
        removed = bool(store.delete(target))
    except Exception:
        removed = False
    if removed:
        credential["status"] = "cleared_after_ready"
        payload["runner_manager_credential"] = credential
        return payload
    credential["status"] = "cleanup_failed"
    payload["runner_manager_credential"] = credential
    payload["security_ready"] = False
    payload["remediation"] = (
        "Runner reached ready state, but its temporary manager credential could not be removed. "
        "Clear the credential with token-clear before accepting the Runner for production use."
    )
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Provision or resume a policy-bound dedicated Windows GitLab Runner."
    )
    parser.add_argument(
        "action",
        choices=("provision", "resume", "token-set", "token-status", "token-clear"),
    )
    parser.add_argument("--policy-name", required=True)
    parser.add_argument("--profile")
    parser.add_argument(
        "--token-env",
        help="Environment variable containing a token for token-set; the token itself is never accepted as an argument.",
    )
    parser.add_argument(
        "--replace-token",
        action="store_true",
        help="Explicitly replace an existing managed Runner manager credential during token-set.",
    )
    parser.add_argument(
        "--confirm-clear",
        action="store_true",
        help="Required acknowledgement before token-clear removes a managed credential.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not _is_windows_administrator():
        print(
            "GitLab Runner administration requires an elevated Windows process.",
            file=sys.stderr,
        )
        return 2
    token_action = args.action.startswith("token-")
    if token_action and args.profile:
        print("GitLab Runner credential actions do not accept --profile", file=sys.stderr)
        return 2
    if args.action != "token-set" and (args.token_env or args.replace_token):
        print("--token-env and --replace-token are valid only with token-set", file=sys.stderr)
        return 2
    if args.action != "token-clear" and args.confirm_clear:
        print("--confirm-clear is valid only with token-clear", file=sys.stderr)
        return 2
    credentials = _load_credentials()
    server = None if token_action else _load_server()
    try:
        payload = (
            _credential_status(args, credentials)
            if token_action
            else _run_lifecycle(args, server, credentials)
        )
    except Exception as exc:  # noqa: BLE001
        sanitizer = getattr(server, "sanitize_error_text", None) if server is not None else None
        message = sanitizer(str(exc)) if callable(sanitizer) else "operation failed closed"
        print(f"GitLab Runner administration failed: {message}", file=sys.stderr)
        return 2

    print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
    if token_action:
        return 0
    return 0 if payload.get("ready") is True and payload.get("security_ready", True) is True else 3


if __name__ == "__main__":
    raise SystemExit(main())
