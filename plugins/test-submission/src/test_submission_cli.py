from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, TextIO

from test_submission_core import SubmissionError, TestSubmissionController, default_config_path
from test_submission_scheduler import SchedulerError, TestSubmissionScheduler
from test_submission_setup import SetupError, run_setup_operation


COMMAND_NAMES = (
    "setup",
    "preflight",
    "submit",
    "run-once",
    "status",
    "doctor",
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
    parser = JsonArgumentParser(prog="test-submission")
    parser.add_argument("--config", default=str(default_config_path()))
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("setup")
    setup.add_argument("--non-interactive", action="store_true")
    setup.add_argument("--scheduler-mode", choices=("auto", "windows", "systemd", "cron"), default="auto")
    setup.add_argument("--submission-gate-address")
    setup.add_argument("--mail-profile")
    setup.add_argument("--mail-email")
    setup.add_argument("--feishu-directory-url")
    for name in ("preflight", "run-once", "status", "doctor"):
        commands.add_parser(name)
    submit = commands.add_parser("submit")
    submit.add_argument("--input", required=True)
    event = commands.add_parser("get-event")
    event.add_argument("--event-id", required=True)
    event.add_argument("--round-id", required=True, type=int)
    scheduler = commands.add_parser("scheduler")
    scheduler_actions = scheduler.add_subparsers(dest="scheduler_action", required=True)
    for name in ("install", "status", "remove"):
        scheduler_actions.add_parser(name)
    return parser


def _read_json_object(raw: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CliUsageError(f"input must be one JSON object: {exc}") from exc
    if not isinstance(payload, dict):
        raise CliUsageError("input must be one JSON object")
    return payload


def _emit(stdout: TextIO, payload: dict[str, Any]) -> None:
    stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def run_cli(
    argv: list[str],
    *,
    stdout: TextIO = sys.stdout,
    controller_factory: Callable[[Path], Any] = lambda path: TestSubmissionController(path),
    scheduler_factory: Callable[[Path], Any] = lambda path: TestSubmissionScheduler(config_path=path, state_dir=path.parent / "state", poll_minutes=60),
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
                    "submission_gate_address": args.submission_gate_address,
                    "mail_profile": args.mail_profile,
                    "mail_email": args.mail_email,
                    "feishu_directory_url": args.feishu_directory_url,
                },
            )
        elif args.command == "scheduler":
            scheduler = scheduler_factory(config_path)
            runtime_mode = json.loads(config_path.read_text(encoding="utf-8")).get("scheduler_mode", "auto") if config_path.is_file() else "auto"
            result = getattr(scheduler, args.scheduler_action)(mode=runtime_mode)
        else:
            controller = controller_factory(config_path)
            if args.command == "preflight":
                result = controller.preflight()
            elif args.command == "submit":
                result = controller.submit(_read_json_object(args.input))
            elif args.command == "run-once":
                result = controller.run_once()
            elif args.command == "status":
                result = controller.status()
            elif args.command == "doctor":
                result = controller.doctor()
            else:
                result = controller.get_event(event_id=args.event_id, round_id=args.round_id)
        _emit(stdout, {"ok": True, "operation": args.command, "result": result})
        blocked = result.get("status") in {"CAPABILITY_BLOCKED", "SEND_BLOCKED"} or result.get("ready") is False
        return EXIT_BLOCKED if blocked else EXIT_OK
    except (CliUsageError, SetupError) as exc:
        _emit(stdout, {"ok": False, "error": {"code": getattr(exc, "code", "INVALID_ARGUMENT"), "message": str(exc)}})
        return EXIT_USAGE
    except (SubmissionError, SchedulerError, OSError, ValueError, TypeError) as exc:
        _emit(stdout, {"ok": False, "error": {"code": getattr(exc, "code", "SUBMISSION_ERROR"), "message": str(exc)}})
        return EXIT_ERROR


def main() -> int:
    return run_cli(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
