from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, TextIO

from submission_gate_core import SubmissionGateController, SubmissionGateError, default_config_path
from submission_gate_scheduler import SchedulerError, SubmissionGateScheduler
from submission_gate_setup import SetupError, run_setup_operation


COMMAND_NAMES = (
    "setup",
    "preflight",
    "run-once",
    "status",
    "doctor",
    "verify-audit",
    "get-event",
    "scheduler",
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_BLOCKED = 3


class CliUsageError(RuntimeError):
    pass


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliUsageError(message)


def build_parser() -> JsonArgumentParser:
    parser = JsonArgumentParser(prog="submission-gate")
    parser.add_argument("--config", default=str(default_config_path()))
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("setup")
    setup.add_argument("--non-interactive", action="store_true")
    setup.add_argument("--scheduler-mode", choices=("auto", "windows", "systemd", "cron"), default="auto")
    setup.add_argument("--submission-group-address")
    setup.add_argument("--blocked-notice-address")
    setup.add_argument("--mail-profile")
    setup.add_argument("--mail-email")
    setup.add_argument("--gate-adapter-command", action="append")
    setup.add_argument("--gate-adapter-entrypoint")
    setup.add_argument("--gate-adapter-entrypoint-sha256")
    for name in ("preflight", "run-once", "status", "doctor", "verify-audit"):
        commands.add_parser(name)
    event = commands.add_parser("get-event")
    event.add_argument("--event-id", required=True)
    event.add_argument("--round-id", required=True, type=int)
    scheduler = commands.add_parser("scheduler")
    scheduler_actions = scheduler.add_subparsers(dest="scheduler_action", required=True)
    for name in ("install", "status", "remove"):
        scheduler_actions.add_parser(name)
    return parser


def _emit(stdout: TextIO, payload: dict[str, Any]) -> None:
    stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def run_cli(
    argv: list[str],
    *,
    stdout: TextIO = sys.stdout,
    controller_factory: Callable[[Path], Any] = lambda path: SubmissionGateController(path),
    scheduler_factory: Callable[[Path], Any] = lambda path: SubmissionGateScheduler(
        config_path=path,
        state_dir=path.parent / "state",
        poll_minutes=60,
    ),
    setup_runner: Callable[..., dict[str, Any]] = run_setup_operation,
) -> int:
    try:
        args = build_parser().parse_args(argv)
        config_path = Path(os.path.expandvars(args.config)).expanduser().resolve(strict=False)
        if args.command == "setup":
            result = setup_runner(
                config_path=config_path,
                non_interactive=args.non_interactive,
                scheduler_mode=args.scheduler_mode,
                provided={
                    "submission_group_address": args.submission_group_address,
                    "blocked_notice_address": args.blocked_notice_address,
                    "mail_profile": args.mail_profile,
                    "mail_email": args.mail_email,
                    "gate_adapter_command": args.gate_adapter_command,
                    "gate_adapter_entrypoint": args.gate_adapter_entrypoint,
                    "gate_adapter_entrypoint_sha256": args.gate_adapter_entrypoint_sha256,
                },
            )
        elif args.command == "scheduler":
            scheduler = scheduler_factory(config_path)
            runtime_mode = (
                json.loads(config_path.read_text(encoding="utf-8")).get("scheduler_mode", "auto")
                if config_path.is_file()
                else "auto"
            )
            result = getattr(scheduler, args.scheduler_action)(mode=runtime_mode)
        else:
            controller = controller_factory(config_path)
            if args.command == "preflight":
                result = controller.preflight()
            elif args.command == "run-once":
                result = controller.run_once()
            elif args.command == "status":
                result = controller.status()
            elif args.command == "doctor":
                result = controller.doctor()
            elif args.command == "verify-audit":
                result = controller.verify_audit()
            else:
                result = controller.get_event(event_id=args.event_id, round_id=args.round_id)
        _emit(stdout, {"ok": True, "operation": args.command, "result": result})
        blocked = (
            result.get("status") in {"CAPABILITY_BLOCKED", "RUN_ALREADY_ACTIVE"}
            or result.get("ready") is False
            or int(result.get("blocked") or 0) > 0
            or int(result.get("capability_blocked") or 0) > 0
        )
        return EXIT_BLOCKED if blocked else EXIT_OK
    except (CliUsageError, SetupError) as exc:
        _emit(
            stdout,
            {"ok": False, "error": {"code": getattr(exc, "code", "INVALID_ARGUMENT"), "message": str(exc)}},
        )
        return EXIT_USAGE
    except (SubmissionGateError, SchedulerError, OSError, ValueError, TypeError) as exc:
        _emit(
            stdout,
            {"ok": False, "error": {"code": getattr(exc, "code", "SUBMISSION_GATE_ERROR"), "message": str(exc)}},
        )
        return EXIT_ERROR


def main() -> int:
    return run_cli(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
