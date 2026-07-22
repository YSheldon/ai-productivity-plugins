from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import sys
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)


LOCATOR_SCHEMA = "ProductMaterialGatePipelineLocator/v1"
HANDOFF_SCHEMA = "ProductMaterialWorkflow/v1"
HANDOFF_STAGE = "RELEASE_GATE_REQUESTED"
VERIFIED_RECEIPT_SCHEMA = "ProductMaterialGateVerifiedReceipt/v1"
LIVE_JOB_NAME = "live_gate"
REQUIRED_GATE_STAGES = (
    "source_retrieval",
    "provenance_validation",
    "nonempty_validation",
    "pre_release_binding",
    "audit_record",
)

_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
_CI_ID_PATTERN = re.compile(r"^[1-9][0-9]*$")
_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_JSON_BYTES = 1024 * 1024
_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_MAX_ARCHIVE_FILES = 512


class ReceiptVerificationError(RuntimeError):
    """A stable fail-closed GitLab receipt verification error."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _canonical_bytes(value: Any, *, ensure_ascii: bool) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=ensure_ascii,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _require_digest(value: Any, label: str) -> str:
    normalized = str(value or "").strip().lower()
    if _DIGEST_PATTERN.fullmatch(normalized) is None:
        raise ReceiptVerificationError(f"{label} has an invalid digest")
    return normalized


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ReceiptVerificationError(f"{label} must be a positive integer")
    if isinstance(value, int):
        normalized = value
    elif isinstance(value, str) and _CI_ID_PATTERN.fullmatch(value):
        normalized = int(value, 10)
    else:
        raise ReceiptVerificationError(f"{label} must be a positive integer")
    if normalized < 1:
        raise ReceiptVerificationError(f"{label} must be a positive integer")
    return normalized


def _read_json_file(path: Path, label: str, *, max_bytes: int) -> dict[str, Any]:
    candidate = Path(path)
    if not candidate.is_file() or candidate.is_symlink():
        raise ReceiptVerificationError(f"{label} must be a regular local file")
    try:
        size = candidate.stat().st_size
        if size < 2 or size > max_bytes:
            raise ReceiptVerificationError(f"{label} has an invalid size")
        raw = candidate.read_bytes()
    except OSError as exc:
        raise ReceiptVerificationError(f"{label} could not be read") from exc
    if len(raw) != size:
        raise ReceiptVerificationError(f"{label} changed while it was read")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptVerificationError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ReceiptVerificationError(f"{label} must contain one JSON object")
    return payload


def _validate_locator(
    payload: Mapping[str, Any],
    *,
    expected_project_id: int,
) -> tuple[int, int]:
    if set(payload) != {"schema", "project_id", "pipeline_id", "job_id"}:
        raise ReceiptVerificationError("pipeline locator fields are invalid")
    if payload.get("schema") != LOCATOR_SCHEMA:
        raise ReceiptVerificationError("pipeline locator schema is invalid")
    project_id = _positive_int(payload.get("project_id"), "project_id")
    if project_id != expected_project_id:
        raise ReceiptVerificationError("pipeline locator project does not match")
    return (
        _positive_int(payload.get("pipeline_id"), "pipeline_id"),
        _positive_int(payload.get("job_id"), "job_id"),
    )


def _validate_handoff(
    handoff: Mapping[str, Any],
    *,
    event_id: str,
    request_sha256: str,
    manifest_r_digest: str,
) -> None:
    required = {
        "schema",
        "stage",
        "event_id",
        "request",
        "request_sha256",
        "source",
        "created_at",
    }
    if set(handoff) != required:
        raise ReceiptVerificationError("handoff fields are invalid")
    request = handoff.get("request")
    source = handoff.get("source")
    if (
        handoff.get("schema") != HANDOFF_SCHEMA
        or handoff.get("stage") != HANDOFF_STAGE
        or handoff.get("event_id") != event_id
        or not isinstance(request, Mapping)
        or request.get("request_id") != event_id
        or not isinstance(source, Mapping)
    ):
        raise ReceiptVerificationError("handoff identity is invalid")
    actual_request_digest = _sha256_digest(
        _canonical_bytes(request, ensure_ascii=False)
    )
    if (
        actual_request_digest != request_sha256
        or handoff.get("request_sha256") != request_sha256
    ):
        raise ReceiptVerificationError("handoff request digest does not match")
    if source.get("manifest_sha256") != manifest_r_digest:
        raise ReceiptVerificationError("handoff Manifest-R digest does not match")


def _validate_api_base(api_url: str, allowed_host: str) -> str:
    parsed = urlparse(api_url)
    if (
        parsed.scheme.casefold() != "https"
        or parsed.hostname is None
        or parsed.hostname.casefold() != allowed_host.casefold()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ReceiptVerificationError(
            "GitLab API must use the configured HTTPS host"
        )
    return api_url.rstrip("/")


def _http_get(
    url: str,
    token: str,
    *,
    max_bytes: int,
    timeout_seconds: int,
) -> bytes:
    request = Request(
        url,
        method="GET",
        headers={
            "PRIVATE-TOKEN": token,
            "Accept": "application/json, application/zip",
            "User-Agent": "ProductReleaseGateGitLabVerifier/1",
        },
    )
    opener = build_opener(
        _NoRedirect(),
        HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            if int(response.status) != 200:
                raise ReceiptVerificationError("GitLab returned a non-success status")
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    declared_size = int(content_length, 10)
                except ValueError as exc:
                    raise ReceiptVerificationError(
                        "GitLab returned an invalid Content-Length"
                    ) from exc
                if declared_size < 1 or declared_size > max_bytes:
                    raise ReceiptVerificationError(
                        "GitLab response exceeds the configured size limit"
                    )
            raw = response.read(max_bytes + 1)
    except ReceiptVerificationError:
        raise
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise ReceiptVerificationError("GitLab request failed") from exc
    if not raw or len(raw) > max_bytes:
        raise ReceiptVerificationError(
            "GitLab response has an invalid size"
        )
    return raw


def _json_fetcher(
    api_base: str,
    token: str,
    *,
    timeout_seconds: int,
) -> Callable[[str], dict[str, Any]]:
    def fetch(path: str) -> dict[str, Any]:
        raw = _http_get(
            api_base + path,
            token,
            max_bytes=_MAX_JSON_BYTES,
            timeout_seconds=timeout_seconds,
        )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReceiptVerificationError(
                "GitLab returned invalid JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise ReceiptVerificationError(
                "GitLab returned an invalid JSON object"
            )
        return payload

    return fetch


def _archive_fetcher(
    api_base: str,
    token: str,
    *,
    timeout_seconds: int,
) -> Callable[[str], bytes]:
    def fetch(path: str) -> bytes:
        return _http_get(
            api_base + path,
            token,
            max_bytes=_MAX_ARTIFACT_BYTES,
            timeout_seconds=timeout_seconds,
        )

    return fetch


def _archive_payloads(raw: bytes) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    total_size = 0
    try:
        with zipfile.ZipFile(BytesIO(raw), mode="r") as archive:
            entries = archive.infolist()
            if not entries or len(entries) > _MAX_ARCHIVE_FILES:
                raise ReceiptVerificationError(
                    "GitLab artifact archive has an invalid file count"
                )
            for entry in entries:
                path = PurePosixPath(entry.filename.replace("\\", "/"))
                if path.is_absolute() or any(
                    part in {"", ".", ".."} for part in path.parts
                ):
                    raise ReceiptVerificationError(
                        "GitLab artifact archive contains an unsafe path"
                    )
                if entry.is_dir():
                    continue
                if entry.file_size < 1 or entry.file_size > _MAX_JSON_BYTES:
                    raise ReceiptVerificationError(
                        "GitLab artifact member has an invalid size"
                    )
                total_size += entry.file_size
                if total_size > _MAX_ARTIFACT_BYTES:
                    raise ReceiptVerificationError(
                        "GitLab artifact archive expands beyond the size limit"
                    )
                normalized = path.as_posix()
                if normalized in payloads:
                    raise ReceiptVerificationError(
                        "GitLab artifact archive contains a duplicate path"
                    )
                data = archive.read(entry)
                if len(data) != entry.file_size:
                    raise ReceiptVerificationError(
                        "GitLab artifact member size changed during extraction"
                    )
                payloads[normalized] = data
    except (zipfile.BadZipFile, OSError) as exc:
        raise ReceiptVerificationError(
            "GitLab artifact archive is invalid"
        ) from exc
    return payloads


def _single_suffix(
    payloads: Mapping[str, bytes],
    suffix: str,
) -> tuple[str, bytes]:
    matches = [
        (path, raw)
        for path, raw in payloads.items()
        if path == suffix or path.endswith("/" + suffix)
    ]
    if len(matches) != 1:
        raise ReceiptVerificationError(
            f"GitLab artifacts must contain exactly one {suffix}"
        )
    return matches[0]


def _json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptVerificationError(f"{label} is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ReceiptVerificationError(f"{label} must be a JSON object")
    return payload


def _validate_artifact_manifest(
    payloads: Mapping[str, bytes],
    manifest_path: str,
    manifest_raw: bytes,
) -> tuple[dict[str, Any], str]:
    manifest = _json_bytes(manifest_raw, "artifact-manifest.json")
    if set(manifest) != {
        "schema_version",
        "payload_manifest_sha256",
        "files",
        "manifest_sha256",
    } or manifest.get("schema_version") != 1:
        raise ReceiptVerificationError("artifact manifest schema is invalid")
    files = manifest.get("files")
    payload_digest = manifest.get("payload_manifest_sha256")
    claimed_digest = manifest.get("manifest_sha256")
    if (
        not isinstance(files, list)
        or not files
        or not isinstance(payload_digest, str)
        or _SHA256_PATTERN.fullmatch(payload_digest) is None
        or not isinstance(claimed_digest, str)
        or _SHA256_PATTERN.fullmatch(claimed_digest) is None
    ):
        raise ReceiptVerificationError("artifact manifest fields are invalid")
    semantic = {
        "schema_version": 1,
        "payload_manifest_sha256": payload_digest,
        "files": files,
    }
    if hashlib.sha256(_canonical_bytes(semantic, ensure_ascii=True)).hexdigest() != claimed_digest:
        raise ReceiptVerificationError("artifact manifest semantic digest is invalid")
    root = manifest_path[: -len("artifact-manifest.json")]
    seen: set[str] = set()
    payload_entries: list[dict[str, Any]] = []
    for entry in files:
        if not isinstance(entry, Mapping) or set(entry) != {
            "relative_path",
            "size_bytes",
            "sha256",
        }:
            raise ReceiptVerificationError("artifact manifest file entry is invalid")
        relative = str(entry.get("relative_path") or "")
        size = entry.get("size_bytes")
        digest = entry.get("sha256")
        if (
            not relative
            or relative in seen
            or "\\" in relative
            or PurePosixPath(relative).is_absolute()
            or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 1
            or not isinstance(digest, str)
            or _SHA256_PATTERN.fullmatch(digest) is None
        ):
            raise ReceiptVerificationError("artifact manifest file binding is invalid")
        data = payloads.get(root + relative)
        if data is None or len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ReceiptVerificationError(
                "artifact manifest does not match the downloaded archive"
            )
        seen.add(relative)
        if relative != "runtime-attestation.json":
            payload_entries.append(
                {
                    "relative_path": relative,
                    "size_bytes": size,
                    "sha256": digest,
                }
            )
    expected_payload_digest = hashlib.sha256(
        _canonical_bytes(payload_entries, ensure_ascii=True)
    ).hexdigest()
    if expected_payload_digest != payload_digest:
        raise ReceiptVerificationError(
            "artifact payload manifest digest is invalid"
        )
    for required in ("gate-result.json", "runtime-attestation.json"):
        if required not in seen:
            raise ReceiptVerificationError(
                f"artifact manifest does not bind {required}"
            )
    return manifest, _sha256_digest(manifest_raw)


def _validate_gate_result(
    payload: Mapping[str, Any],
    *,
    event_id: str,
) -> str:
    verdict = str(payload.get("verdict") or "").upper()
    if (
        payload.get("artifact_profile") != "ci_safe_summary_v1"
        or payload.get("request_id") != event_id
        or verdict not in {"CLEAN", "BLOCKED"}
    ):
        raise ReceiptVerificationError("gate result identity or verdict is invalid")
    stages = payload.get("stages")
    if not isinstance(stages, list):
        raise ReceiptVerificationError("gate result stages are invalid")
    by_name: dict[str, str] = {}
    for stage in stages:
        if not isinstance(stage, Mapping):
            raise ReceiptVerificationError("gate result stage is invalid")
        name = str(stage.get("name") or "")
        status = str(stage.get("status") or "").upper()
        if not name or name in by_name:
            raise ReceiptVerificationError("gate result stage names are invalid")
        by_name[name] = status
    missing = [name for name in REQUIRED_GATE_STAGES if name not in by_name]
    if missing:
        raise ReceiptVerificationError("gate result omits a mandatory stage")
    if verdict == "CLEAN" and any(
        by_name[name] != "CLEAN" for name in REQUIRED_GATE_STAGES
    ):
        raise ReceiptVerificationError(
            "CLEAN verdict has a non-CLEAN mandatory stage"
        )
    if verdict == "BLOCKED" and not any(
        status == "BLOCKED" for status in by_name.values()
    ):
        raise ReceiptVerificationError(
            "BLOCKED verdict has no blocked stage"
        )
    return verdict


def verify_gitlab_receipt(
    *,
    locator: Mapping[str, Any],
    handoff: Mapping[str, Any],
    event_id: str,
    request_sha256: str,
    manifest_r_digest: str,
    expected_project_id: int,
    expected_ref: str,
    fetch_json: Callable[[str], dict[str, Any]],
    fetch_bytes: Callable[[str], bytes],
    verified_at: str | None = None,
) -> dict[str, Any]:
    if _ID_PATTERN.fullmatch(event_id) is None:
        raise ReceiptVerificationError("event_id is invalid")
    request_digest = _require_digest(request_sha256, "request_sha256")
    manifest_digest = _require_digest(manifest_r_digest, "manifest_r_digest")
    pipeline_id, job_id = _validate_locator(
        locator,
        expected_project_id=expected_project_id,
    )
    _validate_handoff(
        handoff,
        event_id=event_id,
        request_sha256=request_digest,
        manifest_r_digest=manifest_digest,
    )
    encoded_project = quote(str(expected_project_id), safe="")
    pipeline = fetch_json(
        f"/projects/{encoded_project}/pipelines/{pipeline_id}"
    )
    job = fetch_json(f"/projects/{encoded_project}/jobs/{job_id}")
    branch = fetch_json(
        f"/projects/{encoded_project}/repository/branches/"
        + quote(expected_ref, safe="")
    )
    commit_sha = str(pipeline.get("sha") or "").lower()
    job_pipeline = job.get("pipeline")
    job_commit = job.get("commit")
    if (
        _positive_int(pipeline.get("id"), "pipeline.id") != pipeline_id
        or str(pipeline.get("ref") or "") != expected_ref
        or _SHA_PATTERN.fullmatch(commit_sha) is None
        or not isinstance(job_pipeline, Mapping)
        or _positive_int(job_pipeline.get("id"), "job.pipeline.id") != pipeline_id
        or _positive_int(job.get("id"), "job.id") != job_id
        or job.get("name") != LIVE_JOB_NAME
        or str(job.get("ref") or "") != expected_ref
        or not isinstance(job_commit, Mapping)
        or str(job_commit.get("id") or "").lower() != commit_sha
        or job.get("tag") is not False
        or branch.get("protected") is not True
        or branch.get("name") != expected_ref
    ):
        raise ReceiptVerificationError(
            "GitLab pipeline, job, commit, or protected ref binding is invalid"
        )
    artifact_raw = fetch_bytes(
        f"/projects/{encoded_project}/jobs/{job_id}/artifacts"
    )
    archive = _archive_payloads(artifact_raw)
    manifest_path, artifact_manifest_raw = _single_suffix(
        archive,
        "artifact-manifest.json",
    )
    artifact_manifest, artifact_manifest_digest = _validate_artifact_manifest(
        archive,
        manifest_path,
        artifact_manifest_raw,
    )
    _, gate_result_raw = _single_suffix(archive, "gate-result.json")
    _, attestation_raw = _single_suffix(
        archive,
        "runtime-attestation.json",
    )
    gate_result = _json_bytes(gate_result_raw, "gate-result.json")
    attestation = _json_bytes(attestation_raw, "runtime-attestation.json")
    verdict = _validate_gate_result(gate_result, event_id=event_id)
    if (
        attestation.get("schema_version") != 1
        or attestation.get("mode") != "live"
        or str(attestation.get("project_id") or "")
        != str(expected_project_id)
        or _positive_int(attestation.get("pipeline_id"), "attestation.pipeline_id")
        != pipeline_id
        or _positive_int(attestation.get("job_id"), "attestation.job_id")
        != job_id
        or str(attestation.get("reviewed_commit") or "").lower()
        != commit_sha
        or attestation.get("request_id") != event_id
        or attestation.get("request_sha256") != request_digest
        or attestation.get("network_service_in_tcb") is not True
        or attestation.get("ci_snapshot_manifest_sha256")
        != artifact_manifest.get("payload_manifest_sha256")
    ):
        raise ReceiptVerificationError(
            "runtime attestation does not bind the protected request and job"
        )
    pipeline_status = str(pipeline.get("status") or "").lower()
    job_status = str(job.get("status") or "").lower()
    if verdict == "CLEAN":
        if pipeline_status != "success" or job_status != "success":
            raise ReceiptVerificationError(
                "CLEAN evidence requires a successful pipeline and live_gate job"
            )
    elif pipeline_status != "failed" or job_status != "failed":
        raise ReceiptVerificationError(
            "BLOCKED evidence requires the fail-closed pipeline and live_gate job"
        )
    timestamp = verified_at or datetime.now(timezone.utc).isoformat().replace(
        "+00:00",
        "Z",
    )
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReceiptVerificationError("verified_at is invalid") from exc
    if parsed.tzinfo is None:
        raise ReceiptVerificationError("verified_at must include a timezone")
    return {
        "schema": VERIFIED_RECEIPT_SCHEMA,
        "verification_status": "VERIFIED",
        "verdict": verdict,
        "event_id": event_id,
        "request_sha256": request_digest,
        "manifest_r_digest": manifest_digest,
        "project_id": expected_project_id,
        "pipeline_id": pipeline_id,
        "job_id": job_id,
        "commit_sha": commit_sha,
        "gate_result_sha256": _sha256_digest(gate_result_raw),
        "artifact_manifest_sha256": artifact_manifest_digest,
        "evidence_ref": (
            f"gitlab:{expected_project_id}/pipelines/{pipeline_id}/jobs/{job_id}"
        ),
        "verified_at": timestamp,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify one protected GitLab product-material-gate job and emit a "
            "Manifest-R-bound CLEAN or BLOCKED receipt."
        )
    )
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--handoff", required=True, type=Path)
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--request-digest", required=True)
    parser.add_argument("--manifest-r-digest", required=True)
    parser.add_argument("--gitlab-project-id", required=True, type=int)
    parser.add_argument(
        "--gitlab-api-url",
        default=os.environ.get(
            "PRODUCT_RELEASE_GATE_GITLAB_API_URL",
            "https://git.falonsecurity.com/api/v4",
        ),
    )
    parser.add_argument(
        "--gitlab-allowed-host",
        default=os.environ.get(
            "PRODUCT_RELEASE_GATE_GITLAB_ALLOWED_HOST",
            "git.falonsecurity.com",
        ),
    )
    parser.add_argument(
        "--gitlab-ref",
        default=os.environ.get("PRODUCT_RELEASE_GATE_GITLAB_REF", "main"),
    )
    parser.add_argument(
        "--gitlab-token-env",
        default="PRODUCT_RELEASE_GATE_GITLAB_TOKEN",
    )
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if not args.json:
            raise ReceiptVerificationError("--json is required")
        if args.timeout_seconds < 1 or args.timeout_seconds > 300:
            raise ReceiptVerificationError("timeout must be between 1 and 300 seconds")
        token = os.environ.get(args.gitlab_token_env, "")
        if len(token) < 16:
            raise ReceiptVerificationError("GitLab verifier token is unavailable")
        api_base = _validate_api_base(
            args.gitlab_api_url,
            args.gitlab_allowed_host,
        )
        locator = _read_json_file(
            args.receipt,
            "pipeline locator",
            max_bytes=64 * 1024,
        )
        handoff = _read_json_file(
            args.handoff,
            "SVN live handoff",
            max_bytes=2 * 1024 * 1024,
        )
        result = verify_gitlab_receipt(
            locator=locator,
            handoff=handoff,
            event_id=args.event_id,
            request_sha256=args.request_digest,
            manifest_r_digest=args.manifest_r_digest,
            expected_project_id=args.gitlab_project_id,
            expected_ref=args.gitlab_ref,
            fetch_json=_json_fetcher(
                api_base,
                token,
                timeout_seconds=args.timeout_seconds,
            ),
            fetch_bytes=_archive_fetcher(
                api_base,
                token,
                timeout_seconds=args.timeout_seconds,
            ),
        )
    except ReceiptVerificationError as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "RECEIPT_VERIFICATION_FAILED",
                    "detail": str(exc),
                },
                ensure_ascii=True,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
