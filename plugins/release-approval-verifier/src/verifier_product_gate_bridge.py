from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


_SOURCE_ROOT = Path(__file__).resolve().parent
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from verifier_config import default_config_path, load_config  # noqa: E402
from verifier_controller import VerifierController  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="release-approval-verifier-bridge")
    parser.add_argument("--config", type=Path, default=default_config_path())
    parser.add_argument("--verification-ref", required=True)
    return parser


def verify_for_product_gate(
    *,
    config_path: str | Path,
    verification_ref: str | Path,
) -> dict[str, Any]:
    resolved_config = Path(config_path).expanduser().resolve(strict=True)
    receipt_path = Path(verification_ref).expanduser().resolve(strict=True)
    controller = VerifierController(
        config=load_config(resolved_config),
        config_path=resolved_config,
    )
    verified = controller.verify_receipt(path=receipt_path)
    receipt = verified["receipt"]
    event = controller.get_event(
        event_id=str(receipt["event_id"]),
        round_id=int(receipt["round_id"]),
    )
    request = event["request"]
    if request["request_digest"] != receipt["request_digest"]:
        raise RuntimeError("receipt request digest differs from the frozen verifier event")
    return {
        "aggregate_status": receipt["status"],
        "verification_ref": str(receipt_path),
        "event_id": receipt["event_id"],
        "round_id": receipt["round_id"],
        "manifest_s_digest": receipt["manifest_s_digest"],
        "manifest_r_digest": receipt["manifest_r_digest"],
        "role_snapshot_digest": receipt["role_snapshot_digest"],
        "target_scope": request["target_scope"],
        "expires_at": receipt["expires_at"],
        "evidence_ref": receipt["receipt_id"],
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = verify_for_product_gate(
            config_path=args.config,
            verification_ref=args.verification_ref,
        )
    except Exception as exc:
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 1
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
