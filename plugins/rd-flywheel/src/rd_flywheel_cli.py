from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, TextIO

_SOURCE_ROOT = Path(__file__).resolve().parent
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from rd_flywheel_adapters import AdapterError, load_runtime_adapters
from rd_flywheel_config import ConfigError, default_config_path, load_config
from rd_flywheel_controller import ControllerError, RDFlywheelController
from rd_flywheel_protocol import ProtocolError, STATES
from rd_flywheel_scheduler import RDFlywheelScheduler, SchedulerError
from rd_flywheel_setup import SetupError, run_setup_operation
from rd_flywheel_store import AuditTamperError, StoreError


EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_USAGE = 2
EXIT_BLOCKED = 3
EXIT_PENDING = 4
EXIT_BUSY = 5
EXIT_NOT_FOUND = 6


class CliUsageError(ValueError):
    """Raised instead of allowing argparse to terminate the process."""


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliUsageError(message)


def _default_controller_factory(config_path: Path) -> RDFlywheelController:
    config = load_config(config_path)
    agents, verifiers = load_runtime_adapters(config)
    return RDFlywheelController(
        config,
        agent_adapters=agents,
        evidence_verifiers=verifiers,
    )


def _default_scheduler_factory(config_path: Path) -> RDFlywheelScheduler:
    config = load_config(config_path)
    return RDFlywheelScheduler(
        config_path=config_path,
        cli_path=Path(__file__).resolve(),
        state_dir=config.state_dir,
        poll_minutes=config.poll_minutes,
    )


def _build_parser() -> JsonArgumentParser:
    parser = JsonArgumentParser(prog="rd-flywheel")
    parser.add_argument(
        "--config",
        default=str(default_config_path()),
        help="Single managed config used by MCP, CLI, Skill, and scheduler.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    setup = subparsers.add_parser("setup")
    setup.add_argument("--non-interactive", action="store_true")
    setup.add_argument("--governance-inbox")
    setup.add_argument("--state-dir")
    setup.add_argument("--agent-profile")
    setup.add_argument(
        "--scheduler-mode",
        default="auto",
        choices=("auto", "windows", "systemd", "cron"),
    )

    for name in ("preflight", "run-once", "status", "doctor", "verify-audit"):
        subparsers.add_parser(name)

    list_events = subparsers.add_parser("list-events")
    list_events.add_argument("--state", choices=STATES)

    get_event = subparsers.add_parser("get-event")
    get_event.add_argument("idempotency_key")

    retry_event = subparsers.add_parser("retry-event")
    retry_event.add_argument("idempotency_key")

    scheduler = subparsers.add_parser("scheduler")
    scheduler.add_argument("action", choices=("install", "status", "remove"))
    scheduler.add_argument(
        "--mode",
        default="auto",
        choices=("auto", "windows", "systemd", "cron"),
    )
    return parser


def run_cli(
    argv: Sequence[str],
    *,
    controller_factory: Callable[[Path], Any] = _default_controller_factory,
    setup_runner: Callable[..., Mapping[str, Any]] = run_setup_operation,
    scheduler_factory: Callable[[Path], Any] = _default_scheduler_factory,
    stdout: TextIO | None = None,
) -> int:
    output = stdout or sys.stdout
    try:
        args = _build_parser().parse_args(list(argv))
        config_path = Path(args.config).expanduser().resolve(strict=False)
        if args.command == "setup":
            payload = setup_runner(
                config_path=config_path,
                non_interactive=args.non_interactive,
                governance_inbox=args.governance_inbox,
                state_dir=args.state_dir,
                agent_profile=args.agent_profile,
                scheduler_mode=args.scheduler_mode,
            )
        elif args.command == "scheduler":
            scheduler = scheduler_factory(config_path)
            operation = getattr(scheduler, args.action)
            payload = operation(mode=args.mode)
        else:
            controller = controller_factory(config_path)
            if args.command == "preflight":
                payload = controller.preflight()
            elif args.command == "run-once":
                payload = controller.run_once()
            elif args.command == "status":
                payload = controller.status()
            elif args.command == "doctor":
                payload = controller.doctor()
            elif args.command == "list-events":
                payload = controller.list_events(state=args.state)
            elif args.command == "get-event":
                payload = controller.get_event(args.idempotency_key)
            elif args.command == "retry-event":
                payload = controller.retry_event(args.idempotency_key)
            elif args.command == "verify-audit":
                payload = controller.verify_audit()
            else:
                raise CliUsageError(f"unsupported command: {args.command}")
        _write_json(output, payload)
        return _exit_for_payload(payload)
    except CliUsageError as exc:
        payload = _error_payload("INVALID_ARGUMENT", str(exc))
        _write_json(output, payload)
        return EXIT_USAGE
    except (
        ConfigError,
        SetupError,
        SchedulerError,
        AdapterError,
        ProtocolError,
        StoreError,
        AuditTamperError,
        ControllerError,
    ) as exc:
        code = str(getattr(exc, "code", type(exc).__name__.upper()))
        payload = _error_payload(code, str(exc))
        _write_json(output, payload)
        return _exit_for_error_code(code)
    except Exception as exc:
        payload = _error_payload(
            "INTERNAL_ERROR",
            f"{type(exc).__name__}: {exc}",
        )
        _write_json(output, payload)
        return EXIT_INTERNAL


def _write_json(output: TextIO, payload: Mapping[str, Any]) -> None:
    output.write(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def _error_payload(code: str, message: str) -> dict[str, Any]:
    return {
        "status": "error",
        "error": {"code": code, "message": message},
    }


def _exit_for_payload(payload: Mapping[str, Any]) -> int:
    status = str(payload.get("status") or "")
    if status in {"ready", "COMPLETE", "not_initialized"}:
        return EXIT_OK
    if status == "CAPABILITY_BLOCKED":
        return EXIT_BLOCKED
    if status == "EVIDENCE_PENDING":
        return EXIT_PENDING
    if status == "RUN_ALREADY_ACTIVE":
        return EXIT_BUSY
    if status == "error":
        code = str(
            (payload.get("error") or {}).get("code")
            if isinstance(payload.get("error"), Mapping)
            else ""
        )
        return _exit_for_error_code(code)
    return EXIT_INTERNAL


def _exit_for_error_code(code: str) -> int:
    if code in {"INVALID_ARGUMENT", "CONFIGERROR", "CONFIG_ERROR"}:
        return EXIT_USAGE
    if code == "EVENT_NOT_FOUND":
        return EXIT_NOT_FOUND
    if "BLOCKED" in code or "UNAVAILABLE" in code:
        return EXIT_BLOCKED
    return EXIT_INTERNAL


def main(argv: Sequence[str] | None = None) -> int:
    return run_cli(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    raise SystemExit(main())
