from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import stat
import sys
from datetime import datetime, timezone
from http.client import RemoteDisconnected
from pathlib import Path
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


SCOPE_FORMAT = "gitlab-mr-approval-scope/v1"
SCOPE_FILE_ENV = "GITLAB_APPROVAL_SCOPE_FILE"
MAX_SCOPE_BYTES = 256 * 1024
MAX_API_RESPONSE_BYTES = 256 * 1024
DEFAULT_TIMEOUT_SECONDS = 15
COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")
POSITIVE_DECIMAL_PATTERN = re.compile(r"^[1-9][0-9]*$")
TOP_LEVEL_FIELDS = frozenset(
    {
        "format",
        "candidate_sha",
        "target_branch",
        "approval_source",
        "merge_request_iid",
        "prepared_at",
        "approved_at",
        "prepared_by",
        "approved_by",
        "scope",
    }
)
SCOPE_FIELDS = frozenset({"id", "items"})
CREDENTIAL_TEXT_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(
        r"\b(?:api[_-]?key|job[_-]?token|password|passwd|private[_-]?token|secret)\s*[:=]",
        re.IGNORECASE,
    ),
    re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", re.IGNORECASE),
)


class GateError(Exception):
    pass


class DuplicateJSONKey(ValueError):
    pass


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


def require_environment(environ: Mapping[str, str], name: str) -> str:
    value = str(environ.get(name) or "").strip()
    if not value:
        raise GateError(f"required CI environment variable is missing: {name}")
    if any(character in value for character in ("\r", "\n", "\0")):
        raise GateError(f"required CI environment variable is malformed: {name}")
    return value


def normalize_api_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.rstrip("/").endswith("/api/v4")
    ):
        raise GateError("CI_API_V4_URL must be an absolute GitLab /api/v4 URL")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise GateError("CI_API_V4_URL must use HTTPS")
    return value.rstrip("/")


def positive_decimal(value: str, name: str) -> str:
    if POSITIVE_DECIMAL_PATTERN.fullmatch(value) is None:
        raise GateError(f"{name} must be a positive decimal value")
    return value


def exact_integer(value: Any) -> bool:
    return type(value) is int


def decode_json_object(content: bytes, label: str) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DuplicateJSONKey(key)
            result[key] = value
        return result

    try:
        text = content.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except DuplicateJSONKey as exc:
        raise GateError(f"{label} contains a duplicate JSON key") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError(f"{label} is malformed JSON") from exc
    if not isinstance(value, dict):
        raise GateError(f"{label} is malformed JSON")
    return value


def fetch_json(url: str, token: str, label: str) -> dict[str, Any]:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "JOB-TOKEN": token,
            "User-Agent": "codex-gitlab-approval-gate/1",
        },
        method="GET",
    )
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirectHandler())
    try:
        with opener.open(request, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
            content = response.read(MAX_API_RESPONSE_BYTES + 1)
            if len(content) > MAX_API_RESPONSE_BYTES:
                raise GateError(f"GitLab {label} response is too large")
            return decode_json_object(content, f"GitLab {label} response")
    except HTTPError as exc:
        raise GateError(f"GitLab {label} request returned status {exc.code}") from exc
    except (URLError, RemoteDisconnected, ConnectionError, TimeoutError, OSError) as exc:
        raise GateError(f"GitLab {label} transport failed") from exc


def validate_merge_request(
    value: dict[str, Any],
    iid: str,
    candidate_sha: str,
    target_branch: str,
) -> None:
    if not exact_integer(value.get("iid")) or str(value["iid"]) != iid:
        raise GateError("GitLab merge request IID differs from the CI pipeline")
    if value.get("state") != "opened":
        raise GateError("GitLab merge request must remain opened")
    actual_sha = value.get("sha")
    if not isinstance(actual_sha, str) or actual_sha.casefold() != candidate_sha.casefold():
        raise GateError("GitLab merge request candidate differs from CI_COMMIT_SHA")
    if value.get("target_branch") != target_branch:
        raise GateError("GitLab merge request target branch differs from the CI pipeline")


def validate_approval(value: dict[str, Any]) -> tuple[int, set[str]]:
    approved = value.get("approved")
    approvals_left = value.get("approvals_left")
    approvals_required = value.get("approvals_required")
    approved_by = value.get("approved_by")
    if (
        type(approved) is not bool
        or not exact_integer(approvals_left)
        or approvals_left < 0
        or not exact_integer(approvals_required)
        or approvals_required < 1
        or not isinstance(approved_by, list)
    ):
        raise GateError("GitLab approval response is malformed")
    if approved is not True or approvals_left != 0:
        raise GateError("GitLab MR approval is not complete")

    usernames: set[str] = set()
    for item in approved_by:
        if not isinstance(item, dict) or not isinstance(item.get("user"), dict):
            raise GateError("GitLab approval response is malformed")
        username = item["user"].get("username")
        if not isinstance(username, str) or SAFE_ID_PATTERN.fullmatch(username) is None:
            raise GateError("GitLab approval response is malformed")
        usernames.add(username)
    if not usernames:
        raise GateError("GitLab approval response is malformed")
    return approvals_required, usernames


def read_private_scope_file(path: Path) -> bytes:
    try:
        initial = os.lstat(path)
    except OSError as exc:
        raise GateError("approval scope file is unavailable") from exc
    if stat.S_ISLNK(initial.st_mode) or not stat.S_ISREG(initial.st_mode):
        raise GateError("approval scope file must be a regular file and not a symlink")
    if initial.st_size < 1 or initial.st_size > MAX_SCOPE_BYTES:
        raise GateError("approval scope file size is invalid")
    if os.name != "nt" and initial.st_mode & 0o022:
        raise GateError("approval scope file must not be writable by group or world")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise GateError("approval scope file could not be opened securely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != initial.st_dev
            or opened.st_ino != initial.st_ino
            or opened.st_size != initial.st_size
        ):
            raise GateError("approval scope file changed while opening")
        chunks: list[bytes] = []
        remaining = MAX_SCOPE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(content) != initial.st_size or len(content) > MAX_SCOPE_BYTES:
        raise GateError("approval scope file changed while reading")
    return content


def contains_credential_text(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            contains_credential_text(key) or contains_credential_text(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(contains_credential_text(item) for item in value)
    if not isinstance(value, str):
        return False
    return any(pattern.search(value) is not None for pattern in CREDENTIAL_TEXT_PATTERNS)


def parse_utc_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GateError(f"approval scope {field} must be a UTC timestamp")
    try:
        timestamp = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GateError(f"approval scope {field} must be a UTC timestamp") from exc
    if timestamp.tzinfo is None or timestamp.astimezone(timezone.utc).year < 2000:
        raise GateError(f"approval scope {field} must be a non-zero UTC timestamp")
    return timestamp.astimezone(timezone.utc)


def validate_scope_manifest(
    value: dict[str, Any],
    candidate_sha: str,
    target_branch: str,
    iid: str,
    api_approvers: set[str],
) -> str:
    if contains_credential_text(value):
        raise GateError("approval scope must not contain credential material")
    fields = frozenset(value)
    if fields != TOP_LEVEL_FIELDS:
        raise GateError("approval scope contains unknown or missing fields")
    if value.get("format") != SCOPE_FORMAT:
        raise GateError("approval scope format is unsupported")
    manifest_sha = value.get("candidate_sha")
    if not isinstance(manifest_sha, str) or manifest_sha.casefold() != candidate_sha.casefold():
        raise GateError("approval scope candidate differs from CI_COMMIT_SHA")
    if value.get("target_branch") != target_branch:
        raise GateError("approval scope target branch differs from the CI pipeline")
    if value.get("approval_source") != "gitlab_mr":
        raise GateError("approval scope approval source must be gitlab_mr")
    if value.get("merge_request_iid") != iid:
        raise GateError("approval scope MR IID differs from the CI pipeline")

    prepared_at = parse_utc_timestamp(value.get("prepared_at"), "prepared_at")
    approved_at = parse_utc_timestamp(value.get("approved_at"), "approved_at")
    if approved_at < prepared_at:
        raise GateError("approval scope approval predates preparation")
    prepared_by = value.get("prepared_by")
    approved_by = value.get("approved_by")
    if (
        not isinstance(prepared_by, str)
        or SAFE_ID_PATTERN.fullmatch(prepared_by) is None
        or not isinstance(approved_by, str)
        or SAFE_ID_PATTERN.fullmatch(approved_by) is None
    ):
        raise GateError("approval scope identities are malformed")
    if prepared_by == approved_by:
        raise GateError("approval scope preparer and approver must be different")
    if approved_by not in api_approvers:
        raise GateError("approval scope approver is not present in the GitLab approval response")

    scope = value.get("scope")
    if not isinstance(scope, dict) or frozenset(scope) != SCOPE_FIELDS:
        raise GateError("approval scope payload contains unknown or missing fields")
    scope_id = scope.get("id")
    items = scope.get("items")
    if not isinstance(scope_id, str) or SAFE_ID_PATTERN.fullmatch(scope_id) is None:
        raise GateError("approval scope id is malformed")
    if not isinstance(items, list) or not items or len(items) > 1000:
        raise GateError("approval scope item inventory must be non-empty")
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, str) or SAFE_ID_PATTERN.fullmatch(item) is None:
            raise GateError("approval scope item is malformed")
        if item in seen:
            raise GateError("approval scope contains a duplicate scope item")
        seen.add(item)
    return scope_id


def verify_release_gate(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    env = os.environ if environ is None else environ
    api_url = normalize_api_url(require_environment(env, "CI_API_V4_URL"))
    if require_environment(env, "CI_PIPELINE_SOURCE") != "merge_request_event":
        raise GateError("approval scope gate requires a merge request pipeline")
    if require_environment(env, "CI_MERGE_REQUEST_EVENT_TYPE") != "detached":
        raise GateError("approval scope gate currently requires a detached MR pipeline")
    project_id = positive_decimal(require_environment(env, "CI_PROJECT_ID"), "CI_PROJECT_ID")
    merge_request_project_id = positive_decimal(
        require_environment(env, "CI_MERGE_REQUEST_PROJECT_ID"),
        "CI_MERGE_REQUEST_PROJECT_ID",
    )
    if merge_request_project_id != project_id:
        raise GateError("merge request project differs from the pipeline project")
    iid = positive_decimal(require_environment(env, "CI_MERGE_REQUEST_IID"), "CI_MERGE_REQUEST_IID")
    job_id = positive_decimal(require_environment(env, "CI_JOB_ID"), "CI_JOB_ID")
    token = require_environment(env, "CI_JOB_TOKEN")
    if len(token) > 4096:
        raise GateError("CI_JOB_TOKEN is malformed")
    candidate_sha = require_environment(env, "CI_COMMIT_SHA")
    if COMMIT_SHA_PATTERN.fullmatch(candidate_sha) is None:
        raise GateError("CI_COMMIT_SHA must be a 40-character commit SHA")
    candidate_sha = candidate_sha.casefold()
    target_branch = require_environment(env, "CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
    if len(target_branch) > 255:
        raise GateError("CI merge request target branch is malformed")
    scope_path_value = require_environment(env, SCOPE_FILE_ENV)
    if os.name == "nt" and scope_path_value.startswith(("\\\\", "//")):
        raise GateError(f"{SCOPE_FILE_ENV} must reference a local file")
    scope_path = Path(scope_path_value)
    if not scope_path.is_absolute():
        raise GateError(f"{SCOPE_FILE_ENV} must be an absolute file path")

    mr_path = (
        f"/projects/{quote(project_id, safe='')}/merge_requests/"
        f"{quote(iid, safe='')}"
    )
    merge_request = fetch_json(api_url + mr_path, token, "merge request")
    validate_merge_request(merge_request, iid, candidate_sha, target_branch)
    approval = fetch_json(api_url + mr_path + "/approvals", token, "approval")
    approvals_required, api_approvers = validate_approval(approval)

    scope_bytes = read_private_scope_file(scope_path)
    scope_sha256 = hashlib.sha256(scope_bytes).hexdigest()
    manifest = decode_json_object(scope_bytes, "approval scope")
    scope_id = validate_scope_manifest(
        manifest,
        candidate_sha,
        target_branch,
        iid,
        api_approvers,
    )
    if read_private_scope_file(scope_path) != scope_bytes:
        raise GateError("approval scope file changed after validation")

    return {
        "ok": True,
        "project_id": project_id,
        "merge_request_iid": iid,
        "candidate_sha": candidate_sha,
        "target_branch": target_branch,
        "approved": True,
        "approvals_left": 0,
        "approvals_required": approvals_required,
        "scope_sha256": scope_sha256,
        "scope_format": SCOPE_FORMAT,
        "scope_id": scope_id,
        "job_id": job_id,
    }


def main() -> int:
    try:
        result = verify_release_gate()
    except GateError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")), file=sys.stderr)
        return 1
    except Exception:
        print(
            json.dumps(
                {"ok": False, "error": "unexpected verifier failure; details suppressed"},
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
