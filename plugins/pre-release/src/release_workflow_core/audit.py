from __future__ import annotations

import base64
import hashlib
import hmac
import os
from pathlib import Path
from typing import Any, Mapping

from .validation import ValidationError, canonical_json


class AuditError(RuntimeError):
    """Raised when the append-only audit log is missing, inconsistent, or tampered."""


class JsonlAuditLog:
    def __init__(self, path: str | Path, *, audit_key: bytes) -> None:
        if not isinstance(audit_key, bytes) or len(audit_key) < 32:
            raise AuditError("audit_key must contain at least 32 bytes.")
        self.path = Path(path)
        self.audit_key = audit_key

    def append(self, record: Mapping[str, Any], *, recorded_at: str) -> dict[str, Any]:
        text = str(recorded_at or "").strip()
        if not text:
            raise AuditError("recorded_at is required for audit append.")
        entries = self._load_verified_entries()
        prev_head = entries[-1]["head_hash"] if entries else "0" * 64
        entry = self._build_entry(len(entries), dict(record), recorded_at=text, prev_head_hash=prev_head)
        lines = [canonical_json(existing) for existing in entries]
        lines.append(canonical_json(entry))
        self._atomic_write("\n".join(lines) + "\n")
        return entry

    def verify(self) -> dict[str, Any]:
        entries = self._load_verified_entries()
        if entries:
            return {"count": len(entries), "head_hash": entries[-1]["head_hash"]}
        return {"count": 0, "head_hash": "0" * 64}

    def verify_audit_checkpoint(self, count: int, head_hash: str) -> None:
        checkpoint = self.verify()
        if checkpoint["count"] != count or checkpoint["head_hash"] != str(head_hash or "").lower():
            raise AuditError("audit checkpoint does not match the current audit head.")

    def _load_verified_entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries: list[dict[str, Any]] = []
        prev_head = "0" * 64
        for index, line in enumerate(self.path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                entry = __import__("json").loads(line)
            except Exception as exc:
                raise AuditError(f"audit line {index + 1} is not valid JSON.") from exc
            if not isinstance(entry, dict):
                raise AuditError(f"audit line {index + 1} must be an object.")
            self._verify_entry(entry, expected_index=len(entries), expected_prev_head=prev_head)
            prev_head = entry["head_hash"]
            entries.append(entry)
        return entries

    def _verify_entry(self, entry: Mapping[str, Any], *, expected_index: int, expected_prev_head: str) -> None:
        if entry.get("index") != expected_index:
            raise AuditError("audit entry index chain is invalid.")
        if entry.get("prev_head_hash") != expected_prev_head:
            raise AuditError("audit entry previous head hash does not match.")
        recorded_at = str(entry.get("recorded_at") or "").strip()
        if not recorded_at:
            raise AuditError("audit entry recorded_at is required.")
        record = entry.get("record")
        if not isinstance(record, Mapping):
            raise AuditError("audit entry record must be an object.")
        record_digest = "sha256:" + hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()
        if entry.get("record_digest") != record_digest:
            raise AuditError("audit entry record digest does not match the stored record.")
        expected_head = self._head_hash(
            index=expected_index,
            recorded_at=recorded_at,
            record=record,
            record_digest=record_digest,
            prev_head_hash=expected_prev_head,
        )
        if entry.get("head_hash") != expected_head:
            raise AuditError("audit entry head hash does not match the record chain.")
        signature = str(entry.get("entry_hmac") or "")
        if signature != self._entry_hmac({key: value for key, value in entry.items() if key != "entry_hmac"}):
            raise AuditError("audit entry HMAC does not match.")

    def _build_entry(
        self,
        index: int,
        record: Mapping[str, Any],
        *,
        recorded_at: str,
        prev_head_hash: str,
    ) -> dict[str, Any]:
        record_digest = "sha256:" + hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()
        head_hash = self._head_hash(
            index=index,
            recorded_at=recorded_at,
            record=record,
            record_digest=record_digest,
            prev_head_hash=prev_head_hash,
        )
        entry = {
            "index": index,
            "recorded_at": recorded_at,
            "record": dict(record),
            "record_digest": record_digest,
            "prev_head_hash": prev_head_hash,
            "head_hash": head_hash,
        }
        entry["entry_hmac"] = self._entry_hmac(entry)
        return entry

    @staticmethod
    def _head_hash(
        *,
        index: int,
        recorded_at: str,
        record: Mapping[str, Any],
        record_digest: str,
        prev_head_hash: str,
    ) -> str:
        payload = {
            "index": index,
            "recorded_at": recorded_at,
            "record": dict(record),
            "record_digest": record_digest,
            "prev_head_hash": prev_head_hash,
        }
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def _entry_hmac(self, payload: Mapping[str, Any]) -> str:
        digest = hmac.new(self.audit_key, canonical_json(payload).encode("utf-8"), hashlib.sha256).digest()
        return "base64:" + base64.b64encode(digest).decode("ascii")

    def _atomic_write(self, content: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.path.with_name(self.path.name + ".tmp")
        temp_path.write_text(content, encoding="utf-8")
        os.replace(temp_path, self.path)
