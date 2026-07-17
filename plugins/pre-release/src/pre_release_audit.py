from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


def canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hmac_text(secret: bytes, value: str) -> str:
    return hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()


class AuditChain:
    def __init__(self, state_dir: str | Path, secret_path: str | Path) -> None:
        self.state_dir = Path(state_dir).resolve(strict=False)
        self.secret_path = Path(secret_path).resolve(strict=False)
        self.audit_dir = self.state_dir / "audit"
        self.entries_dir = self.audit_dir / "entries"

    def append(self, *, event_type: str, status: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        self.entries_dir.mkdir(parents=True, exist_ok=True)
        verification = self.verify()
        if verification["valid"] is not True:
            raise RuntimeError("audit chain is not valid")
        previous = verification.get("last_record_sha256") or ("0" * 64)
        sequence = int(verification.get("entry_count") or 0) + 1
        base = {
            "schema": "PluginAuditRecord/v1",
            "seq": sequence,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event_type": event_type,
            "status": status,
            "payload": dict(payload),
            "prev_record_sha256": previous,
        }
        record_sha256 = _sha256_text(canonical_json(base))
        envelope = {**base, "record_sha256": record_sha256}
        if self.secret_path.exists():
            envelope["signature_mode"] = "hmac"
            envelope["hmac_sha256"] = _hmac_text(self.secret_path.read_bytes(), canonical_json(envelope))
        else:
            envelope["signature_mode"] = "none"
            envelope["hmac_sha256"] = ""
        destination = self.entries_dir / f"{sequence:010d}.json"
        temporary = self.entries_dir / f".{sequence:010d}.tmp-{os.getpid()}"
        temporary.write_text(json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temporary, destination)
        return envelope

    def verify(self) -> dict[str, Any]:
        if not self.entries_dir.exists():
            return {
                "status": "ready",
                "valid": True,
                "entry_count": 0,
                "last_record_sha256": "0" * 64,
                "signature_mode": "hmac" if self.secret_path.exists() else "none",
            }
        previous = "0" * 64
        count = 0
        secret = self.secret_path.read_bytes() if self.secret_path.exists() else None
        for path in sorted(self.entries_dir.glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            count += 1
            expected_seq = count
            if int(payload.get("seq") or 0) != expected_seq:
                return {"status": "CAPABILITY_BLOCKED", "valid": False, "reason": "sequence_mismatch", "path": str(path), "entry_count": count - 1}
            base = {
                "schema": payload.get("schema"),
                "seq": payload.get("seq"),
                "created_at": payload.get("created_at"),
                "event_type": payload.get("event_type"),
                "status": payload.get("status"),
                "payload": payload.get("payload"),
                "prev_record_sha256": payload.get("prev_record_sha256"),
            }
            if base["prev_record_sha256"] != previous:
                return {"status": "CAPABILITY_BLOCKED", "valid": False, "reason": "previous_hash_mismatch", "path": str(path), "entry_count": count - 1}
            expected_record_sha = _sha256_text(canonical_json(base))
            if payload.get("record_sha256") != expected_record_sha:
                return {"status": "CAPABILITY_BLOCKED", "valid": False, "reason": "record_sha256_mismatch", "path": str(path), "entry_count": count - 1}
            signature_mode = str(payload.get("signature_mode") or "none")
            envelope = {**base, "record_sha256": payload.get("record_sha256"), "signature_mode": signature_mode}
            if signature_mode == "hmac":
                if secret is None:
                    return {"status": "CAPABILITY_BLOCKED", "valid": False, "reason": "hmac_secret_unavailable", "path": str(path), "entry_count": count - 1}
                expected_hmac = _hmac_text(secret, canonical_json(envelope))
                if payload.get("hmac_sha256") != expected_hmac:
                    return {"status": "CAPABILITY_BLOCKED", "valid": False, "reason": "hmac_mismatch", "path": str(path), "entry_count": count - 1}
            elif signature_mode == "none":
                if str(payload.get("hmac_sha256") or ""):
                    return {"status": "CAPABILITY_BLOCKED", "valid": False, "reason": "unexpected_hmac", "path": str(path), "entry_count": count - 1}
            else:
                return {"status": "CAPABILITY_BLOCKED", "valid": False, "reason": "signature_mode_invalid", "path": str(path), "entry_count": count - 1}
            previous = expected_record_sha
        return {"status": "ready", "valid": True, "entry_count": count, "last_record_sha256": previous, "signature_mode": "hmac" if secret is not None else "none"}
