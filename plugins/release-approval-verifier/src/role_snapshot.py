from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from typing import Callable, Sequence

from lark_cli_command import resolve_lark_cli_command

_MARKDOWN_TABLE_LINE_PATTERN = re.compile(r"^\s*\|.*\|\s*$")
_HEADING_PATTERN = re.compile(r"^\s*##\s+")
_EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_BOOLEAN_TRUE = {"true", "yes", "1", "y"}
_BOOLEAN_FALSE = {"false", "no", "0", "n"}


class CapabilityBlockedError(RuntimeError):
    """Raised when a required capability cannot provide a safe verifier input."""


@dataclass(frozen=True)
class RoleRecord:
    role_id: str
    email: str
    required: bool
    enabled: bool


@dataclass(frozen=True)
class RoleSnapshot:
    document_url: str
    heading: str
    roles: tuple[RoleRecord, ...]
    digest: str

    @property
    def required_role_ids(self) -> tuple[str, ...]:
        return tuple(role.role_id for role in self.roles if role.required)


def canonical_json(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def build_lark_fetch_args(
    document_url: str,
    *,
    command_prefix: Sequence[str] | None = None,
) -> list[str]:
    return [
        *(command_prefix or resolve_lark_cli_command()),
        "docs",
        "+fetch",
        "--api-version",
        "v2",
        "--doc",
        document_url,
        "--doc-format",
        "markdown",
        "--as",
        "user",
        "--format",
        "pretty",
    ]


def fetch_role_snapshot(
    document_url: str,
    *,
    heading: str,
    timeout_seconds: float = 30.0,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    command_prefix: Sequence[str] | None = None,
) -> RoleSnapshot:
    args = build_lark_fetch_args(document_url, command_prefix=command_prefix)
    try:
        result = runner(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            check=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CapabilityBlockedError(
            "CAPABILITY_BLOCKED: lark-cli docs +fetch could not run for "
            f"role snapshot: {exc}"
        ) from exc
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise CapabilityBlockedError(
            f"CAPABILITY_BLOCKED: lark-cli docs +fetch failed for role snapshot: {stderr or 'unknown error'}"
        )
    return parse_role_snapshot_markdown(result.stdout or "", document_url=document_url, heading=heading)


def parse_role_snapshot_markdown(markdown: str, *, document_url: str, heading: str) -> RoleSnapshot:
    section_lines = _extract_heading_section(markdown, heading)
    table_lines = _extract_first_table(section_lines)
    roles = _parse_role_table(table_lines)
    digest = _build_snapshot_digest(roles)
    return RoleSnapshot(document_url=document_url, heading=heading, roles=roles, digest=digest)


def _extract_heading_section(markdown: str, heading: str) -> list[str]:
    lines = markdown.splitlines()
    target = heading.strip()
    inside = False
    section: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not inside:
            if stripped == target:
                inside = True
            continue
        if _HEADING_PATTERN.match(stripped):
            break
        section.append(line)
    if not inside:
        raise CapabilityBlockedError(f"CAPABILITY_BLOCKED: required role heading not found: {heading}")
    return section


def _extract_first_table(lines: Sequence[str]) -> list[str]:
    table: list[str] = []
    collecting = False
    for line in lines:
        if _MARKDOWN_TABLE_LINE_PATTERN.match(line):
            table.append(line)
            collecting = True
            continue
        if collecting:
            break
    if len(table) < 2:
        raise CapabilityBlockedError("CAPABILITY_BLOCKED: role section must contain one Markdown table.")
    return table


def _parse_role_table(lines: Sequence[str]) -> tuple[RoleRecord, ...]:
    header = _parse_row(lines[0])
    if [column.strip().lower() for column in header] != ["role_id", "email", "required", "enabled"]:
        raise CapabilityBlockedError(
            "CAPABILITY_BLOCKED: role table must use columns role_id, email, required, enabled."
        )

    roles: list[RoleRecord] = []
    enabled_role_ids: set[str] = set()
    enabled_emails: set[str] = set()
    for raw_line in lines[2:]:
        cells = _parse_row(raw_line)
        if len(cells) != 4:
            raise CapabilityBlockedError("CAPABILITY_BLOCKED: malformed role table row.")
        role_id = cells[0].strip()
        email = cells[1].strip().lower()
        required = _parse_bool(cells[2], field_name="required")
        enabled = _parse_bool(cells[3], field_name="enabled")
        if not role_id:
            raise CapabilityBlockedError("CAPABILITY_BLOCKED: role_id must be non-empty.")
        if not enabled:
            continue
        if not email or not _EMAIL_PATTERN.fullmatch(email):
            raise CapabilityBlockedError(
                "CAPABILITY_BLOCKED: enabled role email must be a valid email address."
            )
        if role_id in enabled_role_ids:
            raise CapabilityBlockedError("CAPABILITY_BLOCKED: duplicate role_id found in enabled role rows.")
        enabled_role_ids.add(role_id)
        if email in enabled_emails:
            raise CapabilityBlockedError("CAPABILITY_BLOCKED: duplicate email found in enabled role rows.")
        enabled_emails.add(email)
        roles.append(RoleRecord(role_id=role_id, email=email, required=required, enabled=True))

    if not roles:
        raise CapabilityBlockedError("CAPABILITY_BLOCKED: role table did not leave any enabled rows.")

    roles.sort(key=lambda role: role.role_id)
    if not any(role.required for role in roles):
        raise CapabilityBlockedError("CAPABILITY_BLOCKED: at least one enabled required role must exist.")
    return tuple(roles)


def _parse_row(line: str) -> list[str]:
    stripped = line.strip()
    if not (stripped.startswith("|") and stripped.endswith("|")):
        raise CapabilityBlockedError("CAPABILITY_BLOCKED: malformed role table row.")
    return [cell.strip() for cell in stripped[1:-1].split("|")]


def _parse_bool(value: str, *, field_name: str) -> bool:
    normalized = value.strip().lower()
    if normalized in _BOOLEAN_TRUE:
        return True
    if normalized in _BOOLEAN_FALSE:
        return False
    raise CapabilityBlockedError(f"CAPABILITY_BLOCKED: {field_name} must be a boolean table cell.")


def _build_snapshot_digest(roles: Sequence[RoleRecord]) -> str:
    canonical_roles = [
        {
            "email": role.email,
            "enabled": role.enabled,
            "required": role.required,
            "role_id": role.role_id,
        }
        for role in roles
    ]
    payload = canonical_json(canonical_roles).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()
