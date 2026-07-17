from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

_SOURCE_ROOT = Path(__file__).resolve().parent
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from verifier_config import ConfigError, default_config_path, load_config
from verifier_scheduler import SchedulerError, VerifierScheduler
from verifier_setup import SetupError, run_setup_operation


_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = _PLUGIN_ROOT.parents[1]

COMMAND_NAMES = (
    "setup",
    "preflight",
    "run-once",
    "status",
    "doctor",
    "get-event",
    "list-missing-roles",
    "verify-receipt",
    "verify-audit",
    "scheduler",
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_CAPABILITY = 4
EXIT_FRESH_TASK = 5


class CliUsageError(ValueError):
    pass


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliUsageError(message)


ControllerFactory = Callable[[Path], Any]
SchedulerFactory = Callable[[Path], Any]
SetupRunner = Callable[..., Mapping[str, Any]]


def _default_controller_factory(config_path: Path) -> Any:
    from verifier_controller import VerifierController

    return VerifierController(config=load_config(config_path), config_path=config_path)


def _default_scheduler_factory(config_path: Path) -> VerifierScheduler:
    config = load_config(config_path)
    return VerifierScheduler(
        plugin_name="release-approval-verifier",
        role_id="runtime",
        config_path=config_path,
        state_dir=config.state_dir,
        poll_minutes=config.poll_minutes,
    )


def _default_setup_runner(**kwargs: Any) -> Mapping[str, Any]:
    return run_setup_operation(repo_root=_REPO_ROOT, **kwargs)


def _build_parser() -> JsonArgumentParser:
    parser = JsonArgumentParser(description="Independent release-approval verifier runtime")
    parser.add_argument("--config", default=default_config_path(), type=Path)
    commands = parser.add_subparsers(dest="command", required=True)

    setup = commands.add_parser("setup")
    setup.add_argument("--non-interactive", action="store_true")
    setup.add_argument(
        "--scheduler-mode",
        default="auto",
        choices=("auto", "windows", "systemd", "cron", "codex"),
    )
    setup.add_argument("--mail-profile")
    setup.add_argument("--release-group")
    setup.add_argument("--role-document-url")
    setup.add_argument("--audit-document-url")
    setup.add_argument("--trusted-authserv-ids")
    setup.add_argument("--state-dir")

    for name in ("preflight", "run-once", "status", "doctor", "verify-audit"):
        commands.add_parser(name)

    for name in ("get-event", "list-missing-roles"):
        event = commands.add_parser(name)
        event.add_argument("--event-id", required=True)
        event.add_argument("--round-id", required=True, type=int)

    receipt = commands.add_parser("verify-receipt")
    receipt.add_argument("--path", required=True, type=Path)

    scheduler = commands.add_parser("scheduler")
    scheduler_commands = scheduler.add_subparsers(dest="scheduler_action", required=True)
    for action in ("install", "status", "remove"):
        operation = scheduler_commands.add_parser(action)
        operation.add_argument(
            "--mode",
            default="auto",
            choices=("auto", "windows", "systemd", "cron", "codex"),
        )
    return parser


def run_cli(
    argv: Sequence[str],
    *,
    controller_factory: ControllerFactory = _default_controller_factory,
    scheduler_factory: SchedulerFactory = _default_scheduler_factory,
    setup_runner: SetupRunner = _default_setup_runner,
) -> tuple[int, dict[str, Any]]:
    try:
        args = _build_parser().parse_args(list(argv))
        config_path = args.config.expanduser().resolve(strict=False)
        if args.command == "setup":
            payload = dict(
                setup_runner(
                    config_path=config_path,
                    non_interactive=args.non_interactive,
                    scheduler_mode=args.scheduler_mode,
                    provided={
                        "mail_profile": args.mail_profile,
                        "release_group": args.release_group,
                        "role_document_url": args.role_document_url,
                        "audit_document_url": args.audit_document_url,
                        "trusted_authserv_ids": args.trusted_authserv_ids,
                        "state_dir": args.state_dir,
                    },
                )
            )
            return _exit_for_payload(payload), payload
        if args.command == "scheduler":
            scheduler = scheduler_factory(config_path)
            operation = getattr(scheduler, args.scheduler_action)
            payload = dict(operation(mode=args.mode))
            return _exit_for_payload(payload), payload

        controller = controller_factory(config_path)
        operations = {
            "preflight": controller.preflight,
            "run-once": controller.run_once,
            "status": controller.status,
            "doctor": controller.doctor,
            "verify-audit": controller.verify_audit_chain,
        }
        if args.command in operations:
            payload = dict(operations[args.command]())
            return _exit_for_payload(payload), payload
        if args.command == "verify-receipt":
            payload = dict(controller.verify_receipt(path=args.path.expanduser().resolve(strict=False)))
            return _exit_for_payload(payload), payload
        event_arguments = {"event_id": args.event_id, "round_id": args.round_id}
        if args.command == "get-event":
            payload = dict(controller.get_event(**event_arguments))
        else:
            payload = dict(controller.list_missing_roles(**event_arguments))
        return _exit_for_payload(payload), payload
    except (CliUsageError, argparse.ArgumentError) as exc:
        return EXIT_USAGE, _error_payload("INVALID_ARGUMENT", str(exc))
    except (SetupError, SchedulerError) as exc:
        return _exit_for_error_code(exc.code), _error_payload(exc.code, str(exc))
    except (ConfigError, json.JSONDecodeError, OSError) as exc:
        return EXIT_CONFIG, _error_payload("CONFIG_ERROR", str(exc))
    except Exception as exc:
        code = str(getattr(exc, "code", "") or "")
        if code:
            details = getattr(exc, "details", None)
            return _exit_for_error_code(code), _error_payload(code, str(exc), details=details)
        return EXIT_ERROR, _error_payload(
            "UNEXPECTED_ERROR",
            f"Unexpected {type(exc).__name__}: {exc}",
        )


def _error_payload(
    code: str,
    message: str,
    *,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"ok": False, "error_code": code, "message": message}
    if details:
        payload["details"] = dict(details)
    return payload


def _exit_for_payload(payload: Mapping[str, Any]) -> int:
    status = str(payload.get("status") or "")
    if status == "CAPABILITY_BLOCKED":
        return EXIT_CAPABILITY
    if status == "FRESH_TASK_REQUIRED":
        return EXIT_FRESH_TASK
    return EXIT_OK


def _exit_for_error_code(code: str) -> int:
    if code in {"INVALID_ARGUMENT", "INVALID_SETUP_INPUT", "SETUP_INPUT_REQUIRED"}:
        return EXIT_USAGE
    if code in {"STARTUP_CONFIG_ERROR", "CONFIG_ERROR", "DEPENDENCY_LOCK_MISMATCH"}:
        return EXIT_CONFIG
    if code == "FRESH_TASK_REQUIRED":
        return EXIT_FRESH_TASK
    if code == "CAPABILITY_BLOCKED" or code.endswith("_FAILED"):
        return EXIT_CAPABILITY
    return EXIT_ERROR


def main(argv: Sequence[str] | None = None) -> int:
    exit_code, payload = run_cli(sys.argv[1:] if argv is None else argv)
    json.dump(payload, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
