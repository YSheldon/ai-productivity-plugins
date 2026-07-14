from __future__ import annotations

import json
import sys
import traceback
from typing import Any, Callable

from release_gate_core import GateError
from release_gate_production import ProductionReleaseController


SERVER_NAME = "product-release-gate"
SERVER_VERSION = "0.2.0"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
_CONTROLLER = ProductionReleaseController()


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def controller(args: dict[str, Any]) -> ProductionReleaseController:
    if "config_path" in args:
        raise GateError(
            "config_path cannot be supplied per call; set PRODUCT_RELEASE_GATE_CONFIG before server startup"
        )
    return _CONTROLLER


def text_result(data: Any) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(data, ensure_ascii=False, indent=2),
            }
        ]
    }


def error_result(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def preflight(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).preflight()


def create_submission(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).create_submission(
        event_id=args["event_id"],
        task_id=args["task_id"],
        artifacts=args["artifacts"],
        source_ref=args["source_ref"],
        rollback_ref=args["rollback_ref"],
        risk_level=args.get("risk_level", "standard"),
        round_number=args.get("round_number", 1),
        rule_snapshot_id=args.get("rule_snapshot_id"),
        baseline_manifest_path=args.get("baseline_manifest_path"),
        new_round_of=args.get("new_round_of"),
    )


def run_submission_gate(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).run_submission_gate(args["event_id"])


def run_tests(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).run_tests(args["event_id"])


def record_test_result(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).record_test_result(
        args["event_id"],
        args["test_result"],
        args["report_ref"],
        args.get("summary", ""),
    )


def record_test_approval(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).record_test_approval(
        args["event_id"],
        args["decision"],
        args["approval_ref"],
    )


def build_final_release(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).build_final_release(args["event_id"], args["output_dir"])


def run_release_gate(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).run_release_gate(args["event_id"])


def get_event(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).get_event(args["event_id"])


def generate_report(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).generate_report(args["event_id"])


def production_preflight(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).production_preflight()


def request_release_authorization(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).request_release_authorization(
        args["event_id"],
        args["requested_by"],
        args["target_scope"],
    )


def record_release_authorization(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).record_release_authorization(
        args["event_id"],
        args["decision"],
        args["approval_ref"],
        args["approved_by"],
        args["manifest_s_digest"],
        args["manifest_r_digest"],
    )


def ensure_deployment_capabilities(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).ensure_deployment_capabilities(args["event_id"])


def run_deployment_stage(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).run_deployment_stage(args["event_id"], args["stage"])


def run_production_readback(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).run_production_readback(args["event_id"])


def generate_production_report(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).generate_production_report(args["event_id"])


def verify_control_event_chain(args: dict[str, Any]) -> dict[str, Any]:
    return controller(args).verify_control_event_chain(args["event_id"])


CONFIG_PROPERTY: dict[str, Any] = {}


def event_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "event_id": {
                "type": "string",
                "description": "Durable release event identifier.",
            },
            **CONFIG_PROPERTY,
        },
        "required": ["event_id"],
        "additionalProperties": False,
    }


TOOLS: dict[str, dict[str, Any]] = {
    "release_gate_preflight": {
        "description": "Check storage, Authenticode, cloud-scan, and test-orchestrator readiness before starting a release event.",
        "inputSchema": {
            "type": "object",
            "properties": CONFIG_PROPERTY,
            "additionalProperties": False,
        },
        "handler": preflight,
    },
    "release_gate_create_submission": {
        "description": "Freeze submission material into immutable Manifest-S with locally computed SHA1 values and change classification.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string"},
                "task_id": {"type": "string"},
                "artifacts": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "properties": {
                            "logical_name": {"type": "string"},
                            "file_path": {"type": "string"},
                            "source_ref": {"type": "string"},
                        },
                        "required": ["logical_name", "file_path"],
                        "additionalProperties": False,
                    },
                },
                "source_ref": {"type": "string"},
                "rollback_ref": {"type": "string"},
                "risk_level": {
                    "type": "string",
                    "enum": ["standard", "high", "emergency"],
                    "default": "standard",
                },
                "round_number": {"type": "integer", "minimum": 1, "default": 1},
                "rule_snapshot_id": {"type": "string"},
                "baseline_manifest_path": {"type": "string"},
                "new_round_of": {"type": "string"},
                **CONFIG_PROPERTY,
            },
            "required": [
                "event_id",
                "task_id",
                "artifacts",
                "source_ref",
                "rollback_ref",
            ],
            "additionalProperties": False,
        },
        "handler": create_submission,
    },
    "release_gate_run_submission_gate": {
        "description": "Execute every configured T-gate rule. Any FAIL or ERROR blocks testing.",
        "inputSchema": event_schema(),
        "handler": run_submission_gate,
    },
    "release_gate_run_tests": {
        "description": "Run the configured automated test adapter and bind its evidence to the release event.",
        "inputSchema": event_schema(),
        "handler": run_tests,
    },
    "release_gate_record_test_result": {
        "description": "Record a trusted external test result callback when testing is orchestrated outside this plugin.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string"},
                "test_result": {
                    "type": "string",
                    "enum": ["PASS", "FAIL", "BLOCKED"],
                },
                "report_ref": {"type": "string"},
                "summary": {"type": "string"},
                **CONFIG_PROPERTY,
            },
            "required": ["event_id", "test_result", "report_ref"],
            "additionalProperties": False,
        },
        "handler": record_test_result,
    },
    "release_gate_record_test_approval": {
        "description": "Record the auditable approval decision required for high or emergency risk releases.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string"},
                "decision": {"type": "string", "enum": ["APPROVE", "REJECT"]},
                "approval_ref": {"type": "string"},
                **CONFIG_PROPERTY,
            },
            "required": ["event_id", "decision", "approval_ref"],
            "additionalProperties": False,
        },
        "handler": record_test_approval,
    },
    "release_gate_build_final_release": {
        "description": "Produce Manifest-R by copying only approved Manifest-S files into an empty final-material directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string"},
                "output_dir": {"type": "string"},
                **CONFIG_PROPERTY,
            },
            "required": ["event_id", "output_dir"],
            "additionalProperties": False,
        },
        "handler": build_final_release,
    },
    "release_gate_run_release_gate": {
        "description": "Execute every R-gate rule, including physical directory omissions/extras, SHA1, signature, cloud scan, test approval, and rollback evidence.",
        "inputSchema": event_schema(),
        "handler": run_release_gate,
    },
    "release_gate_get_event": {
        "description": "Read the event state and both frozen manifests for audit or recovery.",
        "inputSchema": event_schema(),
        "handler": get_event,
    },
    "release_gate_generate_report": {
        "description": "Generate the durable Markdown gate report and return its local path.",
        "inputSchema": event_schema(),
        "handler": generate_report,
    },
    "release_gate_production_preflight": {
        "description": "Check production authorization, phased deployment, rollback, and readback adapters before requesting release authority.",
        "inputSchema": {
            "type": "object",
            "properties": CONFIG_PROPERTY,
            "additionalProperties": False,
        },
        "handler": production_preflight,
    },
    "release_gate_request_release_authorization": {
        "description": "Freeze a production authorization request bound to the current Manifest-S and Manifest-R digests.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string"},
                "requested_by": {"type": "string"},
                "target_scope": {"type": "string"},
                **CONFIG_PROPERTY,
            },
            "required": ["event_id", "requested_by", "target_scope"],
            "additionalProperties": False,
        },
        "handler": request_release_authorization,
    },
    "release_gate_record_release_authorization": {
        "description": "Record an external approval bound to both manifests and issue a scoped, expiring authorization credential.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string"},
                "decision": {"type": "string", "enum": ["APPROVE", "REJECT"]},
                "approval_ref": {"type": "string"},
                "approved_by": {"type": "string"},
                "manifest_s_digest": {"type": "string"},
                "manifest_r_digest": {"type": "string"},
                **CONFIG_PROPERTY,
            },
            "required": [
                "event_id",
                "decision",
                "approval_ref",
                "approved_by",
                "manifest_s_digest",
                "manifest_r_digest",
            ],
            "additionalProperties": False,
        },
        "handler": record_release_authorization,
    },
    "release_gate_ensure_deployment_capabilities": {
        "description": "Fail closed and create a replayable capability request when a required deployment adapter is missing.",
        "inputSchema": event_schema(),
        "handler": ensure_deployment_capabilities,
    },
    "release_gate_run_deployment_stage": {
        "description": "Run one ordered deployment stage with digest-bound verification and automatic stage rollback on failure.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string"},
                "stage": {
                    "type": "string",
                    "enum": ["preproduction", "production_canary", "production_full"],
                },
                **CONFIG_PROPERTY,
            },
            "required": ["event_id", "stage"],
            "additionalProperties": False,
        },
        "handler": run_deployment_stage,
    },
    "release_gate_run_production_readback": {
        "description": "Verify the deployed production target reports the exact authorized Manifest-R digest.",
        "inputSchema": event_schema(),
        "handler": run_production_readback,
    },
    "release_gate_generate_production_report": {
        "description": "Generate a production report covering authorization, rollout, rollback, readback, and event-chain evidence.",
        "inputSchema": event_schema(),
        "handler": generate_production_report,
    },
    "release_gate_verify_control_event_chain": {
        "description": "Verify the append-only hash chain for production control events.",
        "inputSchema": event_schema(),
        "handler": verify_control_event_chain,
    },
}


def response(request_id: Any, value: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


def error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}
    if request_id is None:
        return None
    try:
        if method == "initialize":
            return response(
                request_id,
                {
                    "protocolVersion": params.get("protocolVersion")
                    or DEFAULT_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            )
        if method == "ping":
            return response(request_id, {})
        if method == "tools/list":
            return response(
                request_id,
                {
                    "tools": [
                        {
                            "name": name,
                            "description": spec["description"],
                            "inputSchema": spec["inputSchema"],
                        }
                        for name, spec in TOOLS.items()
                    ]
                },
            )
        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            if tool_name not in TOOLS:
                raise GateError(f"Unknown tool: {tool_name}")
            handler: Callable[[dict[str, Any]], dict[str, Any]] = TOOLS[tool_name]["handler"]
            return response(request_id, text_result(handler(arguments)))
        return error_response(request_id, -32601, f"Method not found: {method}")
    except (GateError, KeyError, TypeError, ValueError) as exc:
        return response(request_id, error_result(str(exc)))
    except Exception as exc:
        eprint(traceback.format_exc())
        return response(
            request_id,
            error_result(f"Unexpected {type(exc).__name__}: {exc}"),
        )


def send_message(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def run_stdio_server() -> None:
    eprint("Product Release Gate MCP stdio server started")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            send_message(error_response(None, -32700, f"Parse error: {exc}"))
            continue
        result_value = handle_request(message)
        if result_value is not None:
            send_message(result_value)


if __name__ == "__main__":
    run_stdio_server()
