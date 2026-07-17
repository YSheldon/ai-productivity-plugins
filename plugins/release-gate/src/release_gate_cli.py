from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

from release_gate_config import ConfigError, default_config_path, load_config
from release_gate_controller import ReleaseGateController, ReleaseGateError
from release_gate_mail import locked_mail_gateway, locked_product_gate_gateway
from release_workflow_gate_scheduler import ReleaseGateScheduler, SchedulerError
from release_workflow_gate_setup import SetupError, run_setup_operation


COMMAND_NAMES = ("setup", "preflight", "run-once", "status", "doctor", "verify-audit", "scheduler")
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_CAPABILITY = 4


class CliUsageError(ValueError):
    pass


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliUsageError(message)


def _default_controller_factory(config_path: Path) -> ReleaseGateController:
    config = load_config(config_path)
    return ReleaseGateController(
        config,
        mail_gateway=locked_mail_gateway(config.dependency_lock, dependency_lock_sha256=config.dependency_lock_sha256),
        product_gate=locked_product_gate_gateway(config.dependency_lock, dependency_lock_sha256=config.dependency_lock_sha256, config_path=config.product_gate.config_path),
    )


def _default_scheduler_factory(config_path: Path) -> ReleaseGateScheduler:
    config = load_config(config_path)
    return ReleaseGateScheduler(config_path=config_path, state_dir=config.state_dir, poll_minutes=config.poll_minutes)


def _build_parser() -> JsonArgumentParser:
    parser = JsonArgumentParser(description="Release-gate standalone runtime")
    parser.add_argument("--config", default=default_config_path(), type=Path)
    commands = parser.add_subparsers(dest="command", required=True)

    setup = commands.add_parser("setup")
    setup.add_argument("--non-interactive", action="store_true")
    setup.add_argument("--scheduler-mode", default="auto", choices=("auto", "windows", "systemd", "cron", "codex"))
    setup.add_argument("--mail-profile")
    setup.add_argument("--mail-email")
    setup.add_argument("--release-gate-group")
    setup.add_argument("--release-group")
    setup.add_argument("--state-dir")
    setup.add_argument("--product-gate-config-path")

    for name in ("preflight", "run-once", "status", "doctor", "verify-audit"):
        commands.add_parser(name)

    scheduler = commands.add_parser("scheduler")
    scheduler_commands = scheduler.add_subparsers(dest="scheduler_action", required=True)
    for action in ("install", "status", "remove"):
        operation = scheduler_commands.add_parser(action)
        operation.add_argument("--mode", default="auto", choices=("auto", "windows", "systemd", "cron", "codex"))
    return parser


def run_cli(
    argv: Sequence[str],
    *,
    controller_factory: Callable[[Path], Any] = _default_controller_factory,
    scheduler_factory: Callable[[Path], Any] = _default_scheduler_factory,
    setup_runner: Callable[..., dict[str, Any]] = run_setup_operation,
) -> tuple[int, dict[str, Any]]:
    try:
        args = _build_parser().parse_args(list(argv))
        config_path = args.config.expanduser().resolve(strict=False)
        if args.command == "setup":
            payload = dict(
                setup_runner(
                    config_path=config_path,
                    non_interactive=bool(args.non_interactive),
                    scheduler_mode=str(args.scheduler_mode),
                    provided={
                        "mail_profile": args.mail_profile,
                        "mail_email": args.mail_email,
                        "release_gate_group": args.release_gate_group,
                        "release_group": args.release_group,
                        "state_dir": args.state_dir,
                        "product_gate_config_path": args.product_gate_config_path,
                    },
                )
            )
            return _exit_for_payload(payload), payload
        if args.command == "scheduler":
            scheduler = scheduler_factory(config_path)
            payload = getattr(scheduler, args.scheduler_action)(mode=args.mode)
            return _exit_for_payload(payload), dict(payload)
        controller = controller_factory(config_path)
        if args.command == "verify-audit":
            payload = controller.verify_audit()
        else:
            payload = getattr(controller, args.command.replace("-", "_"))()
        return _exit_for_payload(payload), payload
    except (CliUsageError, argparse.ArgumentError) as exc:
        return EXIT_USAGE, {"ok": False, "error_code": "INVALID_ARGUMENT", "message": str(exc)}
    except (SetupError, SchedulerError, ReleaseGateError) as exc:
        return _exit_for_error_code(exc.code), {"ok": False, "error_code": exc.code, "message": str(exc)}
    except (ConfigError, json.JSONDecodeError, OSError) as exc:
        return EXIT_CONFIG, {"ok": False, "error_code": "CONFIG_ERROR", "message": str(exc)}
    except Exception as exc:
        return EXIT_ERROR, {"ok": False, "error_code": "UNEXPECTED_ERROR", "message": f"Unexpected {type(exc).__name__}: {exc}"}


def _exit_for_payload(payload: dict[str, Any]) -> int:
    if payload.get("status") in {"CAPABILITY_BLOCKED", "RUN_ALREADY_ACTIVE"} or payload.get("valid") is False:
        return EXIT_CAPABILITY
    return EXIT_OK


def _exit_for_error_code(code: str) -> int:
    if code == "INVALID_ARGUMENT":
        return EXIT_USAGE
    if code in {"CAPABILITY_BLOCKED", "RUN_ALREADY_ACTIVE"}:
        return EXIT_CAPABILITY
    return EXIT_ERROR


def main(argv: Sequence[str] | None = None) -> int:
    code, payload = run_cli(sys.argv[1:] if argv is None else argv)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
