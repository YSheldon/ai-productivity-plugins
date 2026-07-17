from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Mapping, Protocol


@dataclass(frozen=True)
class WorkflowAuthConfig:
    mode: str = "optional"
    key_id: str = ""
    provider: str = "env"

    def metadata(self) -> dict[str, str | bool]:
        return {
            "enabled": self.mode != "disabled",
            "mode": self.mode,
            "key_id": self.key_id,
            "provider": self.provider,
        }


class WorkflowAuthProvider(Protocol):
    def resolve_secret(self, key_id: str) -> bytes | None:
        ...

    def metadata(self) -> dict[str, str | bool]:
        ...


class EnvWorkflowAuthProvider:
    def __init__(
        self,
        *,
        config: WorkflowAuthConfig | None = None,
        environ: Mapping[str, str] | None = None,
        variable_prefix: str = "RELEASE_WORKFLOW_AUTH_KEY_",
    ) -> None:
        self.config = config or WorkflowAuthConfig()
        self.environ = dict(os.environ if environ is None else environ)
        self.variable_prefix = variable_prefix

    def resolve_secret(self, key_id: str) -> bytes | None:
        resolved_key_id = str(key_id or self.config.key_id or "").strip()
        if not resolved_key_id:
            return None
        raw = self.environ.get(f"{self.variable_prefix}{resolved_key_id.upper()}") or self.environ.get(
            f"{self.variable_prefix}{resolved_key_id}"
        )
        if raw is None:
            return None
        secret = raw.encode("utf-8")
        if len(secret) < 32:
            return None
        return secret

    def metadata(self) -> dict[str, str | bool]:
        return self.config.metadata()


def generate_auth_secret() -> bytes:
    return secrets.token_bytes(32)


def rotate_auth_key_ids(current_key_id: str, previous_key_ids: tuple[str, ...] = ()) -> dict[str, object]:
    return {
        "current_key_id": str(current_key_id or "").strip(),
        "previous_key_ids": [str(item).strip() for item in previous_key_ids if str(item).strip()],
    }
