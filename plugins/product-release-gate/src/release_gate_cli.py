from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, TextIO

_SOURCE_ROOT = Path(__file__).resolve().parent
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from release_gate_core import GateError, default_config_path
from release_gate_production import ProductionReleaseController
from release_gate_runtime import ReleaseGateWorkflowRuntime


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_BLOCKED = 3


class CliUsageError(RuntimeError):
    pass


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliUsageError(message)


CONTROLLER_OPERATIONS = (
    "preflight",
    "create_submission",
    "run_submission_gate",
    "run_tests",
    "record_test_result",
    "record_test_approval",
    "build_final_release",
    "run_release_gate",
    "get_event",
    "generate_report",
    "production_preflight",
    "request_release_authorization",
    "record_release_authorization",
    "finalize_verified_release_authorization",
    "request_unified_release_approval",
    "record_unified_release_approval",
    "ensure_deployment_capabilities",
    "run_deployment_stage",
    "run_production_readback",
    "generate_production_report",
    "deliver_production_report",
    "verify_control_event_chain",
)


def build_parser() -> JsonArgumentParser:
    parser = JsonArgumentParser(prog="product-release-gate")
    parser.add_argument("--config", default=str(default_config_path()))
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "run-once", "status", "doctor", "list-events"):
        commands.add_parser(name)

    enqueue = commands.add_parser("enqueue-handoff")
    enqueue.add_argument("--event-id", required=True)
    enqueue.add_argument("--verification-ref", required=True)

    request = commands.add_parser("request-unified-approval")
    request_input = request.add_mutually_exclusive_group(required=True)
    request_input.add_argument("--input")
    request_input.add_argument("--input-file")

    record = commands.add_parser("record-unified-approval")
    record.add_argument("--event-id", required=True)
    record.add_argument("--verification-ref", required=True)

    call = commands.add_parser("call")
    call.add_argument("operation", choices=CONTROLLER_OPERATIONS)
    call_input = call.add_mutually_exclusive_group()
    call_input.add_argument("--input")
    call_input.add_argument("--input-file")

    setup = commands.add_parser("setup")
    setup.add_argument("--non-interactive", action="store_true")
    setup.add_argument(
        "--scheduler-mode",
        choices=("auto", "windows", "systemd", "cron"),
        default="auto",
    )
    setup.add_argument("--verifier-config")
    setup.add_argument("--module", default="all")

    scheduler = commands.add_parser("scheduler")
    scheduler_actions = scheduler.add_subparsers(
        dest="scheduler_action",
        required=True,
    )
    for action in ("install", "status", "remove"):
        scheduler_actions.add_parser(action)
    return parser


def _read_payload(args: argparse.Namespace) -> dict[str, Any]:
    raw = getattr(args, "input", None)
    input_file = getattr(args, "input_file", None)
    if input_file:
        raw = Path(input_file).read_text(encoding="utf-8")
    if raw is None:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CliUsageError(f"input must be one JSON object: {exc}") from exc
    if not isinstance(payload, dict):
        raise CliUsageError("input must be one JSON object")
    return payload


def invoke_controller(
    controller: Any,
    operation: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    if operation == "preflight":
        return controller.preflight()
    if operation == "create_submission":
        return controller.create_submission(
            event_id=payload["event_id"],
            task_id=payload["task_id"],
            artifacts=payload["artifacts"],
            source_ref=payload["source_ref"],
            rollback_ref=payload["rollback_ref"],
            risk_level=payload.get("risk_level", "standard"),
            round_number=payload.get("round_number", 1),
            rule_snapshot_id=payload.get("rule_snapshot_id"),
            baseline_manifest_path=payload.get("baseline_manifest_path"),
            new_round_of=payload.get("new_round_of"),
        )
    if operation == "run_submission_gate":
        return controller.run_submission_gate(payload["event_id"])
    if operation == "run_tests":
        return controller.run_tests(payload["event_id"])
    if operation == "record_test_result":
        return controller.record_test_result(
            payload["event_id"],
            payload["test_result"],
            payload["report_ref"],
            payload.get("summary", ""),
        )
    if operation == "record_test_approval":
        return controller.record_test_approval(
            payload["event_id"],
            payload["decision"],
            payload["approval_ref"],
        )
    if operation == "build_final_release":
        return controller.build_final_release(
            payload["event_id"],
            payload["output_dir"],
        )
    if operation == "run_release_gate":
        return controller.run_release_gate(payload["event_id"])
    if operation == "get_event":
        return controller.get_event(payload["event_id"])
    if operation == "generate_report":
        return controller.generate_report(payload["event_id"])
    if operation == "production_preflight":
        return controller.production_preflight()
    if operation == "request_release_authorization":
        return controller.request_release_authorization(
            payload["event_id"],
            payload["requested_by"],
            payload["target_scope"],
        )
    if operation == "record_release_authorization":
        return controller.record_release_authorization(
            payload["event_id"],
            payload["decision"],
            payload["approval_ref"],
            payload["approved_by"],
            payload["manifest_s_digest"],
            payload["manifest_r_digest"],
        )
    if operation == "finalize_verified_release_authorization":
        return controller.finalize_verified_release_authorization(
            payload["event_id"]
        )
    if operation == "request_unified_release_approval":
        return controller.request_unified_release_approval(**payload)
    if operation == "record_unified_release_approval":
        return controller.record_unified_release_approval(
            payload["event_id"],
            payload["verification_ref"],
        )
    if operation == "ensure_deployment_capabilities":
        return controller.ensure_deployment_capabilities(payload["event_id"])
    if operation == "run_deployment_stage":
        return controller.run_deployment_stage(
            payload["event_id"],
            payload["stage"],
        )
    if operation == "run_production_readback":
        return controller.run_production_readback(payload["event_id"])
    if operation == "generate_production_report":
        return controller.generate_production_report(payload["event_id"])
    if operation == "deliver_production_report":
        return controller.deliver_production_report(payload["event_id"])
    if operation == "verify_control_event_chain":
        return controller.verify_control_event_chain(payload["event_id"])
    raise CliUsageError(f"unsupported controller operation: {operation}")


def _default_controller_factory(config_path: Path) -> Any:
    return ProductionReleaseController(str(config_path))


def _default_runtime_factory(controller: Any, config_path: Path) -> Any:
    return ReleaseGateWorkflowRuntime(controller, config_path)


def _default_scheduler_factory(controller: Any, config_path: Path) -> Any:
    from release_gate_scheduler import ReleaseGateScheduler

    runtime = controller.config.get("runtime") or {}
    return ReleaseGateScheduler(
        config_path=config_path,
        state_dir=runtime.get("state_dir")
        or controller.storage_dir.parent / "state",
        poll_minutes=runtime.get("poll_minutes", 60),
    )


def _default_setup_runner(**kwargs: Any) -> dict[str, Any]:
    from release_gate_setup import run_setup_operation

    return run_setup_operation(**kwargs)


def _emit(stdout: TextIO, payload: dict[str, Any]) -> None:
    stdout.write(
        json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n"
    )


def _exit_code(result: dict[str, Any]) -> int:
    if result.get("status") in {"CAPABILITY_BLOCKED", "RUN_ALREADY_ACTIVE"}:
        return EXIT_BLOCKED
    if result.get("ready") is False:
        return EXIT_BLOCKED
    return EXIT_OK


def run_cli(
    argv: list[str],
    *,
    stdout: TextIO = sys.stdout,
    controller_factory: Callable[[Path], Any] = _default_controller_factory,
    runtime_factory: Callable[[Any, Path], Any] = _default_runtime_factory,
    scheduler_factory: Callable[[Any, Path], Any] = _default_scheduler_factory,
    setup_runner: Callable[..., dict[str, Any]] = _default_setup_runner,
) -> int:
    try:
        args = build_parser().parse_args(argv)
        config_path = Path(os.path.expandvars(args.config)).expanduser().resolve(
            strict=False
        )
        if args.command == "setup":
            provided: dict[str, Any] = {"module": args.module}
            if args.verifier_config:
                provided["verifier_config_path"] = args.verifier_config
            result = setup_runner(
                config_path=config_path,
                non_interactive=args.non_interactive,
                scheduler_mode=args.scheduler_mode,
                provided=provided,
            )
        else:
            controller = controller_factory(config_path)
            runtime = runtime_factory(controller, config_path)
            if args.command == "preflight":
                result = controller.preflight()
            elif args.command == "run-once":
                result = runtime.run_once()
            elif args.command == "status":
                result = runtime.status()
            elif args.command == "doctor":
                result = runtime.doctor()
            elif args.command == "list-events":
                result = runtime.list_events()
            elif args.command == "enqueue-handoff":
                result = runtime.enqueue_handoff(
                    args.event_id,
                    args.verification_ref,
                )
            elif args.command == "request-unified-approval":
                result = invoke_controller(
                    controller,
                    "request_unified_release_approval",
                    _read_payload(args),
                )
            elif args.command == "record-unified-approval":
                result = controller.record_unified_release_approval(
                    args.event_id,
                    args.verification_ref,
                )
            elif args.command == "call":
                result = invoke_controller(
                    controller,
                    args.operation,
                    _read_payload(args),
                )
            elif args.command == "scheduler":
                scheduler = scheduler_factory(controller, config_path)
                runtime_config = controller.config.get("runtime") or {}
                result = getattr(scheduler, args.scheduler_action)(
                    mode=str(runtime_config.get("scheduler_mode") or "auto")
                )
            else:
                raise CliUsageError(f"unsupported command: {args.command}")
        _emit(
            stdout,
            {"ok": True, "operation": args.command, "result": result},
        )
        return _exit_code(result)
    except CliUsageError as exc:
        _emit(
            stdout,
            {
                "ok": False,
                "error": {
                    "code": "INVALID_ARGUMENT",
                    "message": str(exc),
                },
            },
        )
        return EXIT_USAGE
    except (GateError, KeyError, TypeError, ValueError, OSError, RuntimeError) as exc:
        _emit(
            stdout,
            {
                "ok": False,
                "error": {
                    "code": getattr(exc, "code", "GATE_ERROR"),
                    "message": str(exc),
                },
            },
        )
        return EXIT_ERROR


def main() -> int:
    return run_cli(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
