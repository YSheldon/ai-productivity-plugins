from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

_SOURCE_ROOT = Path(__file__).resolve().parent
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from release_approval_config import ConfigError, default_config_path, load_config
from release_approval_mcp import ReleaseApprovalController, ReleaseApprovalMcpError
from release_approval_scheduler import ReleaseApprovalScheduler, SchedulerError
from release_approval_setup import SetupError, run_setup_operation


_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = _PLUGIN_ROOT.parents[1]

COMMAND_NAMES = (
    "setup",
    "preflight",
    "run-once",
    "status",
    "doctor",
    "list-pending",
    "open-page",
    "get-event",
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
PageWaiter = Callable[..., None]


def _default_controller_factory(config_path: Path) -> ReleaseApprovalController:
    return ReleaseApprovalController(
        config=load_config(config_path),
        config_path=config_path,
    )


def _default_scheduler_factory(config_path: Path) -> ReleaseApprovalScheduler:
    config = load_config(config_path)
    return ReleaseApprovalScheduler(
        plugin_name="release-approval",
        role_id=config.role_id,
        config_path=config_path,
        state_dir=config.state_dir,
        poll_minutes=config.poll_minutes,
    )


def _default_setup_runner(**kwargs: Any) -> Mapping[str, Any]:
    return run_setup_operation(repo_root=_REPO_ROOT, **kwargs)


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def wait_for_page(
    *,
    controller: Any,
    page_result: Mapping[str, Any],
    event_id: str,
    round_id: int,
    role_id: str | None,
) -> None:
    del page_result
    try:
        while True:
            event = controller.get_event(
                event_id=event_id,
                round_id=round_id,
                role_id=role_id,
            )["event"]
            if event.get("current_decision") is not None:
                return
            if datetime.now(timezone.utc) >= _parse_timestamp(str(event["expires_at"])):
                return
            time.sleep(1)
    except KeyboardInterrupt:
        return


def _build_parser() -> JsonArgumentParser:
    parser = JsonArgumentParser(description="Release approval standalone runtime")
    parser.add_argument("--config", default=default_config_path(), type=Path)
    commands = parser.add_subparsers(dest="command", required=True)

    setup = commands.add_parser("setup")
    setup.add_argument("--non-interactive", action="store_true")
    setup.add_argument(
        "--scheduler-mode",
        default="auto",
        choices=("auto", "windows", "systemd", "cron", "codex"),
    )
    setup.add_argument("--role-id")
    setup.add_argument("--role-email")
    setup.add_argument("--mail-profile")
    setup.add_argument("--release-group")
    setup.add_argument("--request-sender-email")
    setup.add_argument("--trusted-authserv-ids")
    setup.add_argument("--state-dir")
    setup.add_argument("--audit-document-url")

    for name in ("preflight", "run-once", "status", "doctor", "list-pending", "verify-audit"):
        commands.add_parser(name)

    for name in ("open-page", "get-event"):
        event = commands.add_parser(name)
        event.add_argument("--event-id", required=True)
        event.add_argument("--round-id", required=True, type=int)
        event.add_argument("--role-id")

    scheduler = commands.add_parser("scheduler")
    scheduler_commands = scheduler.add_subparsers(dest="scheduler_action", required=True)
    install = scheduler_commands.add_parser("install")
    install.add_argument(
        "--mode",
        default="auto",
        choices=("auto", "windows", "systemd", "cron", "codex"),
    )

    for action in ("status", "remove"):
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
    page_waiter: PageWaiter = wait_for_page,
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
                        "role_id": args.role_id,
                        "role_email": args.role_email,
                        "mail_profile": args.mail_profile,
                        "release_group": args.release_group,
                        "request_sender_email": args.request_sender_email,
                        "trusted_authserv_ids": args.trusted_authserv_ids,
                        "state_dir": args.state_dir,
                        "audit_document_url": args.audit_document_url,
                    },
                )
            )
            return _exit_for_payload(payload), payload
        if args.command == "scheduler":
            scheduler = scheduler_factory(config_path)
            if args.scheduler_action == "install":
                payload = scheduler.install(mode=args.mode)
            elif args.scheduler_action == "status":
                payload = scheduler.status(mode=args.mode)
            else:
                payload = scheduler.remove(mode=args.mode)
            result = dict(payload)
            return _exit_for_payload(result), result

        controller = controller_factory(config_path)
        operations = {
            "preflight": controller.preflight,
            "run-once": controller.run_once,
            "status": controller.status,
            "doctor": controller.doctor,
            "list-pending": controller.list_pending,
            "verify-audit": controller.verify_audit_chain,
        }
        if args.command in operations:
            payload = dict(operations[args.command]())
            return _exit_for_payload(payload), payload
        kwargs = {
            "event_id": args.event_id,
            "round_id": args.round_id,
            "role_id": args.role_id,
        }
        if args.command == "get-event":
            payload = dict(controller.get_event(**kwargs))
            return _exit_for_payload(payload), payload
        payload = dict(controller.open_page(**kwargs))
        page_waiter(controller=controller, page_result=payload, **kwargs)
        return _exit_for_payload(payload), payload
    except (CliUsageError, argparse.ArgumentError) as exc:
        return EXIT_USAGE, _error_payload("INVALID_ARGUMENT", str(exc))
    except ReleaseApprovalMcpError as exc:
        return _exit_for_error_code(exc.code), _error_payload(
            exc.code,
            str(exc),
            details=exc.details,
        )
    except (SetupError, SchedulerError) as exc:
        return _exit_for_error_code(exc.code), _error_payload(exc.code, str(exc))
    except (ConfigError, json.JSONDecodeError, OSError) as exc:
        return EXIT_CONFIG, _error_payload("CONFIG_ERROR", str(exc))
    except Exception as exc:
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
