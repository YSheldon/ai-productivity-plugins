from __future__ import annotations

import base64
import hashlib
import json
import ntpath
import os
import re
import ssl
import time
import tomllib
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


SERVER_NAME = "gitlab"
SERVER_VERSION = "0.2.4"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
DEFAULT_GITLAB_URL = "https://gitlab.com"
DEFAULT_TIMEOUT_SECONDS = 30
MAX_LIMIT = 100
REDACTED = "[REDACTED]"
SCHANNEL_HELPER = Path(__file__).resolve().parents[1] / "scripts" / "invoke_schannel.ps1"
RUNNER_POLICY_SCHEMA_VERSION = 1
RUNNER_POLICY_NAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
RUNNER_SERVICE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$")
RUNNER_TAG_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:/-]{0,62}[A-Za-z0-9])?$")
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
RUNNER_POLICY_DIRECTORY_NAME = "runner-policies"
RUNNER_RUNTIME_DIRECTORY_NAME = "runners"
RUNNER_JOURNAL_FILE_NAME = "provisioning-state.json"
RUNNER_IDENTITY_FILE_NAME = "runner-identity.json"
RUNNER_JOURNAL_SCHEMA_VERSION = 1
RUNNER_IDENTITY_SCHEMA = "ProductMaterialGateRunnerIdentity/v1"
SENSITIVE_RESPONSE_KEYS = frozenset(
    {
        "access_token",
        "authorization",
        "client_secret",
        "deploy_token",
        "job_token",
        "password",
        "private_token",
        "refresh_token",
        "registration_token",
        "runner_token",
        "runners_token",
        "secret",
        "set_cookie",
        "token",
    }
)


def normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).casefold()).strip("_")


def is_gitlab_variable_record(value: dict[Any, Any]) -> bool:
    keys = {normalized_key(key) for key in value}
    metadata = {"environment_scope", "masked", "protected", "raw", "variable_type"}
    return {"key", "value"}.issubset(keys) and bool(keys & metadata)


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        variable_record = is_gitlab_variable_record(value)
        return {
            key: (
                REDACTED
                if normalized_key(key) in SENSITIVE_RESPONSE_KEYS
                or (variable_record and normalized_key(key) == "value")
                else redact_sensitive(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive(item) for item in value]
    return value


def sanitize_error_text(value: str, *, secrets: tuple[str, ...] = ()) -> str:
    text = str(value)
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return text
    return json.dumps(redact_sensitive(parsed), ensure_ascii=False)


class ToolError(Exception):
    pass


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def tool_result(data: Any) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(redact_sensitive(data), ensure_ascii=False, indent=2)}]}


def error_result(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": sanitize_error_text(message)}], "isError": True}


def config_path() -> Path:
    raw = os.environ.get("GITLAB_CONFIG")
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".config" / "codex-gitlab" / "config.json"


def load_config() -> dict[str, Any]:
    path = config_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ToolError(f"Invalid GitLab config JSON at {path}: {exc}") from exc


def profile_config(profile: str | None = None) -> dict[str, Any]:
    config = load_config()
    profiles = config.get("profiles") if isinstance(config.get("profiles"), dict) else {}
    selected = profile or config.get("default") or os.environ.get("GITLAB_PROFILE")
    data: dict[str, Any] = {}
    if selected:
        if selected not in profiles:
            raise ToolError(f"GitLab profile not found: {selected}")
        data.update(profiles[selected] or {})
        data["profile"] = selected
    elif profiles:
        first_name = next(iter(profiles))
        data.update(profiles[first_name] or {})
        data["profile"] = first_name
    else:
        data["profile"] = "env"

    data.setdefault("url", os.environ.get("GITLAB_URL") or DEFAULT_GITLAB_URL)
    data.setdefault("token_env", os.environ.get("GITLAB_TOKEN_ENV") or "GITLAB_TOKEN")
    data.setdefault("auth_header", os.environ.get("GITLAB_AUTH_HEADER") or "PRIVATE-TOKEN")

    if "token" not in data:
        token_env = str(data.get("token_env") or "GITLAB_TOKEN")
        token = os.environ.get(token_env)
        if token:
            data["token"] = token

    if not data.get("token"):
        raise ToolError(
            "GitLab token is not configured. Set GITLAB_TOKEN or use GITLAB_CONFIG with token_env."
        )
    return data


def list_profiles(_: dict[str, Any]) -> dict[str, Any]:
    config = load_config()
    profiles = sorted((config.get("profiles") or {}).keys())
    env_ready = bool(os.environ.get("GITLAB_TOKEN"))
    return tool_result(
        {
            "config_path": str(config_path()),
            "default": config.get("default") or os.environ.get("GITLAB_PROFILE") or ("env" if env_ready else None),
            "profiles": profiles,
            "env": {
                "GITLAB_URL": os.environ.get("GITLAB_URL") or DEFAULT_GITLAB_URL,
                "GITLAB_TOKEN_set": env_ready,
            },
        }
    )


def normalize_base_url(url: str) -> str:
    url = (url or DEFAULT_GITLAB_URL).rstrip("/")
    if not url.startswith("http://") and not url.startswith("https://"):
        raise ToolError("GitLab url must start with http:// or https://")
    return url


def encode_project(project: str | int) -> str:
    text = str(project).strip()
    if not text:
        raise ToolError("project is required")
    return quote(text, safe="")


def optional_params(values: dict[str, Any]) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for key, value in values.items():
        if value is None or value == "":
            continue
        if isinstance(value, bool):
            params[key] = "true" if value else "false"
        elif isinstance(value, list):
            params[key] = ",".join(str(item) for item in value if str(item))
        else:
            params[key] = value
    return params


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


@lru_cache(maxsize=1)
def trusted_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    enum_certificates = getattr(ssl, "enum_certificates", None)
    if enum_certificates is None:
        return context

    server_auth_oid = "1.3.6.1.5.5.7.3.1"
    trusted_certificates: list[str] = []
    for store_name in ("ROOT", "CA"):
        for certificate, encoding, trust in enum_certificates(store_name):
            if encoding != "x509_asn":
                continue
            if trust is not True and server_auth_oid not in trust:
                continue
            trusted_certificates.append(ssl.DER_cert_to_PEM_cert(certificate))
    if trusted_certificates:
        context.load_verify_locations(cadata="".join(trusted_certificates))
    return context


def open_url(request: Request, timeout: int) -> Any:
    opener = build_opener(HTTPSHandler(context=trusted_ssl_context()), NoRedirectHandler())
    return opener.open(request, timeout=timeout)


def is_windows_tls_verification_failure(error: URLError) -> bool:
    return os.name == "nt" and isinstance(error.reason, ssl.SSLCertVerificationError)


def windows_system_directory() -> Path | None:
    if os.name != "nt":
        return None
    try:
        import ctypes

        capacity = 32768
        buffer = ctypes.create_unicode_buffer(capacity)
        length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, capacity)
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    if length <= 0 or length >= capacity:
        return None
    return Path(buffer.value)


def system_powershell_path() -> Path | None:
    system_directory = windows_system_directory()
    if system_directory is None:
        return None
    candidate = system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not candidate.is_file():
        return None
    return candidate


def schannel_request(
    method: str,
    url: str,
    headers: dict[str, str],
    data: bytes | None,
    timeout: int,
) -> tuple[int, dict[str, str], bytes]:
    powershell = system_powershell_path()
    if powershell is None or not SCHANNEL_HELPER.is_file():
        raise ToolError("Windows Schannel fallback is unavailable; request failed closed")

    request_payload = {
        "method": method.upper(),
        "url": url,
        "headers": headers,
        "body_base64": base64.b64encode(data).decode("ascii") if data is not None else None,
        "timeout_seconds": max(1, int(timeout)),
    }
    command = [
        str(powershell),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(SCHANNEL_HELPER),
    ]
    completed = subprocess.run(
        command,
        input=json.dumps(request_payload, ensure_ascii=True),
        capture_output=True,
        text=True,
        timeout=max(10, int(timeout) + 5),
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise ToolError("Windows Schannel request failed closed")
    try:
        envelope = json.loads(completed.stdout)
        status = int(envelope["status"])
        response_headers = {str(key): str(value) for key, value in envelope["headers"].items()}
        content = base64.b64decode(envelope["body_base64"], validate=True)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ToolError("Windows Schannel returned an invalid response envelope") from exc
    return status, response_headers, content


class GitLabClient:
    def __init__(self, profile: str | None = None):
        cfg = profile_config(profile)
        self.profile = cfg.get("profile")
        self.base_url = normalize_base_url(str(cfg.get("url")))
        self.token = str(cfg["token"])
        self.auth_header = str(cfg.get("auth_header") or "PRIVATE-TOKEN")
        self.timeout = int(cfg.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)

    def headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": f"codex-gitlab-plugin/{SERVER_VERSION}"}
        auth_header = self.auth_header
        if auth_header.lower() == "authorization":
            headers["Authorization"] = f"Bearer {self.token}"
        else:
            headers[auth_header] = self.token
        return headers

    def api_url(self, path: str, query: dict[str, Any] | None = None) -> str:
        candidate = str(path or "").strip()
        if not candidate or any(character in candidate for character in ("\r", "\n", "\0")):
            raise ToolError("GitLab API path must be a nonempty relative path")
        parsed = urlsplit(candidate)
        if parsed.scheme or parsed.netloc:
            raise ToolError("Absolute or network-path GitLab API URLs are not allowed")
        if parsed.query or parsed.fragment:
            raise ToolError("Put GitLab API query values in the query object, not in path")
        normalized_path = parsed.path
        if not normalized_path.startswith("/"):
            normalized_path = "/" + normalized_path
        if not normalized_path.startswith("/api/"):
            normalized_path = "/api/v4" + normalized_path
        url = self.base_url + normalized_path
        if query:
            url += "?" + urlencode(query, doseq=True)
        return url

    def request(
        self,
        method: str,
        path: str,
        query: dict[str, Any] | None = None,
        body: Any | None = None,
        raw: bool = False,
    ) -> Any:
        headers = self.headers()
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = Request(self.api_url(path, query), data=data, headers=headers, method=method.upper())
        try:
            with open_url(req, self.timeout) as response:
                content = response.read()
                if raw:
                    return {
                        "status": response.status,
                        "headers": dict(response.headers.items()),
                        "body_base64": base64.b64encode(content).decode("ascii"),
                    }
                return decode_response(response.status, content)
        except HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            safe_body = sanitize_error_text(body_text[:2000], secrets=(self.token,))
            raise ToolError(f"GitLab API {exc.code} {exc.reason}: {safe_body}") from exc
        except URLError as exc:
            if not is_windows_tls_verification_failure(exc):
                raise ToolError(f"GitLab connection failed: {exc.reason}") from exc
            status, response_headers, content = schannel_request(
                method,
                self.api_url(path, query),
                headers,
                data,
                self.timeout,
            )
            if status >= 300:
                body_text = content.decode("utf-8", errors="replace")
                safe_body = sanitize_error_text(body_text[:2000], secrets=(self.token,))
                raise ToolError(f"GitLab API {status} through Schannel: {safe_body}")
            if raw:
                return {
                    "status": status,
                    "headers": response_headers,
                    "body_base64": base64.b64encode(content).decode("ascii"),
                }
            return decode_response(status, content)


def decode_response(status: int, content: bytes) -> Any:
    if not content:
        return {"status": status}
    text = content.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"status": status, "text": text}


def limit_from_args(args: dict[str, Any], default: int = 20) -> int:
    limit = int(args.get("limit") or default)
    return max(1, min(limit, MAX_LIMIT))


def client(args: dict[str, Any]) -> GitLabClient:
    return GitLabClient(args.get("profile"))


def test_connection(args: dict[str, Any]) -> dict[str, Any]:
    gl = client(args)
    user = gl.request("GET", "/user")
    version = gl.request("GET", "/version")
    return tool_result(
        {
            "ok": True,
            "profile": gl.profile,
            "url": gl.base_url,
            "user": {
                "id": user.get("id"),
                "username": user.get("username"),
                "name": user.get("name"),
            },
            "version": version,
        }
    )


def current_user(args: dict[str, Any]) -> dict[str, Any]:
    return tool_result(client(args).request("GET", "/user"))


def search_projects(args: dict[str, Any]) -> dict[str, Any]:
    params = optional_params(
        {
            "search": args.get("search"),
            "membership": args.get("membership"),
            "owned": args.get("owned"),
            "visibility": args.get("visibility"),
            "simple": args.get("simple", True),
            "order_by": args.get("order_by") or "last_activity_at",
            "sort": args.get("sort") or "desc",
            "per_page": limit_from_args(args),
        }
    )
    return tool_result(client(args).request("GET", "/projects", params))


def get_project(args: dict[str, Any]) -> dict[str, Any]:
    project = encode_project(args.get("project"))
    return tool_result(client(args).request("GET", f"/projects/{project}"))


def list_merge_requests(args: dict[str, Any]) -> dict[str, Any]:
    params = optional_params(
        {
            "state": args.get("state") or "opened",
            "scope": args.get("scope"),
            "author_username": args.get("author_username"),
            "reviewer_username": args.get("reviewer_username"),
            "assignee_username": args.get("assignee_username"),
            "labels": args.get("labels"),
            "search": args.get("search"),
            "target_branch": args.get("target_branch"),
            "source_branch": args.get("source_branch"),
            "order_by": args.get("order_by") or "updated_at",
            "sort": args.get("sort") or "desc",
            "per_page": limit_from_args(args),
        }
    )
    project = args.get("project")
    path = f"/projects/{encode_project(project)}/merge_requests" if project else "/merge_requests"
    return tool_result(client(args).request("GET", path, params))


def get_merge_request(args: dict[str, Any]) -> dict[str, Any]:
    path = f"/projects/{encode_project(args.get('project'))}/merge_requests/{int(args['iid'])}"
    return tool_result(client(args).request("GET", path))


def list_merge_request_changes(args: dict[str, Any]) -> dict[str, Any]:
    path = f"/projects/{encode_project(args.get('project'))}/merge_requests/{int(args['iid'])}/changes"
    return tool_result(client(args).request("GET", path))


def list_merge_request_discussions(args: dict[str, Any]) -> dict[str, Any]:
    path = f"/projects/{encode_project(args.get('project'))}/merge_requests/{int(args['iid'])}/discussions"
    discussions = client(args).request("GET", path, {"per_page": limit_from_args(args, 50)})
    if args.get("unresolved_only"):
        discussions = [
            discussion
            for discussion in discussions
            if any(note.get("resolvable") and not note.get("resolved") for note in discussion.get("notes", []))
        ]
    return tool_result(discussions)


def create_merge_request(args: dict[str, Any]) -> dict[str, Any]:
    body = optional_params(
        {
            "source_branch": args.get("source_branch"),
            "target_branch": args.get("target_branch"),
            "title": args.get("title"),
            "description": args.get("description"),
            "remove_source_branch": args.get("remove_source_branch"),
            "squash": args.get("squash"),
        }
    )
    if args.get("draft") and body.get("title") and not str(body["title"]).lower().startswith(("draft:", "wip:")):
        body["title"] = "Draft: " + str(body["title"])
    required = ["source_branch", "target_branch", "title"]
    missing = [name for name in required if not body.get(name)]
    if missing:
        raise ToolError("Missing required fields: " + ", ".join(missing))
    path = f"/projects/{encode_project(args.get('project'))}/merge_requests"
    return tool_result(client(args).request("POST", path, body=body))


def update_merge_request(args: dict[str, Any]) -> dict[str, Any]:
    body = optional_params(
        {
            "title": args.get("title"),
            "description": args.get("description"),
            "state_event": args.get("state_event"),
            "add_labels": args.get("add_labels"),
            "remove_labels": args.get("remove_labels"),
            "assignee_ids": args.get("assignee_ids"),
            "reviewer_ids": args.get("reviewer_ids"),
            "target_branch": args.get("target_branch"),
        }
    )
    if not body:
        raise ToolError("No update fields were provided")
    path = f"/projects/{encode_project(args.get('project'))}/merge_requests/{int(args['iid'])}"
    return tool_result(client(args).request("PUT", path, body=body))


def comment_on_merge_request(args: dict[str, Any]) -> dict[str, Any]:
    body = str(args.get("body") or "").strip()
    if not body:
        raise ToolError("body is required")
    path = f"/projects/{encode_project(args.get('project'))}/merge_requests/{int(args['iid'])}/notes"
    return tool_result(client(args).request("POST", path, body={"body": body}))


def approve_merge_request(args: dict[str, Any]) -> dict[str, Any]:
    path = f"/projects/{encode_project(args.get('project'))}/merge_requests/{int(args['iid'])}/approve"
    body = optional_params({"sha": args.get("sha")})
    return tool_result(client(args).request("POST", path, body=body or {}))


def merge_merge_request(args: dict[str, Any]) -> dict[str, Any]:
    body = optional_params(
        {
            "merge_commit_message": args.get("merge_commit_message"),
            "squash_commit_message": args.get("squash_commit_message"),
            "squash": args.get("squash"),
            "should_remove_source_branch": args.get("should_remove_source_branch"),
            "merge_when_pipeline_succeeds": args.get("merge_when_pipeline_succeeds"),
            "sha": args.get("sha"),
        }
    )
    path = f"/projects/{encode_project(args.get('project'))}/merge_requests/{int(args['iid'])}/merge"
    return tool_result(client(args).request("PUT", path, body=body))


def list_issues(args: dict[str, Any]) -> dict[str, Any]:
    params = optional_params(
        {
            "state": args.get("state") or "opened",
            "scope": args.get("scope"),
            "labels": args.get("labels"),
            "search": args.get("search"),
            "assignee_username": args.get("assignee_username"),
            "author_username": args.get("author_username"),
            "order_by": args.get("order_by") or "updated_at",
            "sort": args.get("sort") or "desc",
            "per_page": limit_from_args(args),
        }
    )
    project = args.get("project")
    path = f"/projects/{encode_project(project)}/issues" if project else "/issues"
    return tool_result(client(args).request("GET", path, params))


def get_issue(args: dict[str, Any]) -> dict[str, Any]:
    path = f"/projects/{encode_project(args.get('project'))}/issues/{int(args['iid'])}"
    return tool_result(client(args).request("GET", path))


def comment_on_issue(args: dict[str, Any]) -> dict[str, Any]:
    body = str(args.get("body") or "").strip()
    if not body:
        raise ToolError("body is required")
    path = f"/projects/{encode_project(args.get('project'))}/issues/{int(args['iid'])}/notes"
    return tool_result(client(args).request("POST", path, body={"body": body}))


def list_pipelines(args: dict[str, Any]) -> dict[str, Any]:
    params = optional_params(
        {
            "ref": args.get("ref"),
            "sha": args.get("sha"),
            "status": args.get("status"),
            "source": args.get("source"),
            "order_by": args.get("order_by") or "updated_at",
            "sort": args.get("sort") or "desc",
            "per_page": limit_from_args(args),
        }
    )
    path = f"/projects/{encode_project(args.get('project'))}/pipelines"
    return tool_result(client(args).request("GET", path, params))


def get_pipeline(args: dict[str, Any]) -> dict[str, Any]:
    path = f"/projects/{encode_project(args.get('project'))}/pipelines/{int(args['pipeline_id'])}"
    return tool_result(client(args).request("GET", path))


def list_pipeline_jobs(args: dict[str, Any]) -> dict[str, Any]:
    params = optional_params({"scope": args.get("scope"), "per_page": limit_from_args(args, 50)})
    path = f"/projects/{encode_project(args.get('project'))}/pipelines/{int(args['pipeline_id'])}/jobs"
    return tool_result(client(args).request("GET", path, params))


def get_repository_file(args: dict[str, Any]) -> dict[str, Any]:
    project = encode_project(args.get("project"))
    file_path = quote(str(args.get("file_path") or ""), safe="")
    if not file_path:
        raise ToolError("file_path is required")
    ref = args.get("ref") or "HEAD"
    path = f"/projects/{project}/repository/files/{file_path}"
    data = client(args).request("GET", path, {"ref": ref})
    if args.get("decode", True) and data.get("encoding") == "base64" and data.get("content"):
        decoded = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        data["decoded_content"] = decoded
    return tool_result(data)


RUNNER_POLICY_ALLOWED_FIELDS = frozenset(
    {
        "schema_version",
        "gitlab_url",
        "project",
        "runner_name",
        "tag_list",
        "runner_binary",
        "runner_binary_sha256",
        "install_service",
        "service_name",
        "service_account",
        "timeout_seconds",
    }
)
RUNNER_CHILD_ENV_ALLOWLIST = frozenset(
    {
        "APPDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PSMODULEPATH",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
)


def require_windows_runner_host() -> None:
    if os.name != "nt":
        raise ToolError("Windows Runner provisioning is only available on Windows")


def require_windows_runner_administrator() -> None:
    require_windows_runner_host()
    try:
        import ctypes

        is_administrator = int(ctypes.windll.shell32.IsUserAnAdmin()) == 1
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise ToolError(
            "Windows administrator status could not be verified; Runner provisioning failed closed"
        ) from exc
    if not is_administrator:
        raise ToolError(
            "Dedicated Windows Runner provisioning requires an elevated administrator process"
        )


def runner_child_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in RUNNER_CHILD_ENV_ALLOWLIST
    }
    if extra:
        env.update(extra)
    return env


def run_system_powershell_json(script: str, payload: dict[str, Any]) -> dict[str, Any]:
    powershell = system_powershell_path()
    if powershell is None:
        raise ToolError("Trusted Windows PowerShell is unavailable; Runner provisioning failed closed")
    # PowerShell 7 module paths can shadow incompatible Windows PowerShell 5.1
    # modules such as Microsoft.PowerShell.Security. Let 5.1 build its defaults.
    powershell_environment = {
        key: value for key, value in runner_child_environment().items()
        if key.casefold() != "psmodulepath"
    }
    command = [
        str(powershell),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
    ]
    completed = subprocess.run(
        command,
        input=json.dumps(payload, ensure_ascii=True),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
        env=powershell_environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise ToolError("Trusted Windows path inspection failed closed")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ToolError("Trusted Windows path inspection returned an invalid response") from exc
    if not isinstance(result, dict):
        raise ToolError("Trusted Windows path inspection returned an invalid response")
    return result


def windows_platform_roots() -> dict[str, str]:
    require_windows_runner_host()
    script = r"""
$ErrorActionPreference = 'Stop'
[pscustomobject]@{
  program_data = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  program_files = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
  program_files_x86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
} | ConvertTo-Json -Compress
"""
    roots = run_system_powershell_json(script, {})
    for key in ("program_data", "program_files"):
        if not isinstance(roots.get(key), str) or not ntpath.isabs(str(roots[key])):
            raise ToolError("Windows trusted folder discovery failed closed")
    return {key: str(value) for key, value in roots.items() if isinstance(value, str) and value}


def canonical_windows_path(value: Any, field: str) -> str:
    text = str(value or "").strip().replace("/", "\\")
    if not text or any(character in text for character in ("\r", "\n", "\0")):
        raise ToolError(f"Runner policy {field} must be a nonempty absolute Windows path")
    if not ntpath.isabs(text) or text.startswith(("\\\\", "\\?\\", "\\.\\")):
        raise ToolError(f"Runner policy {field} must be a local drive absolute path")
    drive, _tail = ntpath.splitdrive(text)
    if not re.fullmatch(r"[A-Za-z]:", drive):
        raise ToolError(f"Runner policy {field} must be a local drive absolute path")
    if any(part == ".." for part in text.replace("/", "\\").split("\\")):
        raise ToolError(f"Runner policy {field} cannot contain parent traversal")
    return ntpath.normpath(text)


def windows_path_is_within(path: str, root: str) -> bool:
    try:
        return ntpath.normcase(ntpath.commonpath((path, root))) == ntpath.normcase(ntpath.normpath(root))
    except ValueError:
        return False


def assert_strict_windows_acl(
    path: str,
    stop_path: str,
    *,
    service_write_root: str | None = None,
    require_service_write: bool = False,
) -> None:
    script = r"""
$ErrorActionPreference = 'Stop'
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$target = Get-Item -LiteralPath ([string]$payload.path) -Force
$stop = Get-Item -LiteralPath ([string]$payload.stop_path) -Force
$serviceWriteRoot = $null
if (-not [string]::IsNullOrWhiteSpace([string]$payload.service_write_root)) {
  $serviceWriteRoot = Get-Item -LiteralPath ([string]$payload.service_write_root) -Force
}
$allowedWriters = @('S-1-5-18','S-1-5-32-544')
$allowedOwners = @('S-1-5-18','S-1-5-32-544')
$serviceSid = 'S-1-5-20'
try {
  $trustedInstaller = (New-Object Security.Principal.NTAccount('NT SERVICE','TrustedInstaller')).Translate([Security.Principal.SecurityIdentifier]).Value
  $allowedWriters += $trustedInstaller
  $allowedOwners += $trustedInstaller
} catch {}
# Composite Write/Modify/FullControl values overlap ReadAndExecute through
# ReadPermissions/Synchronize. Only primitive mutation rights are authoritative.
$writeCapable = [Security.AccessControl.FileSystemRights]::WriteData -bor
  [Security.AccessControl.FileSystemRights]::AppendData -bor
  [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
  [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
  [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
  [Security.AccessControl.FileSystemRights]::Delete -bor
  [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
  [Security.AccessControl.FileSystemRights]::TakeOwnership
$cursor = $target
$serviceWriteOnTarget = $false
while ($true) {
  if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse point rejected' }
  $acl = Get-Acl -LiteralPath $cursor.FullName
  $ownerSid = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
  if ($allowedOwners -notcontains $ownerSid) { throw 'untrusted owner rejected' }
  $serviceWriteAllowedHere = $false
  if ($null -ne $serviceWriteRoot) {
    $rootPrefix = $serviceWriteRoot.FullName.TrimEnd('\') + '\'
    $cursorPrefix = $cursor.FullName.TrimEnd('\') + '\'
    $serviceWriteAllowedHere = $cursorPrefix.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)
  }
  foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        (($rule.FileSystemRights -band $writeCapable) -eq 0)) {
      continue
    }
    $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($allowedWriters -notcontains $sid -and -not ($sid -eq $serviceSid -and $serviceWriteAllowedHere)) {
      throw 'untrusted writer ACE rejected'
    }
    if ([StringComparer]::OrdinalIgnoreCase.Equals($cursor.FullName, $target.FullName) -and $sid -eq $serviceSid) {
      $serviceWriteOnTarget = $true
    }
  }
  if ([StringComparer]::OrdinalIgnoreCase.Equals($cursor.FullName, $stop.FullName)) { break }
  if ($cursor -is [IO.FileInfo]) {
    $cursor = $cursor.Directory
  } else {
    $cursor = $cursor.Parent
  }
  if ($null -eq $cursor) { throw 'path escaped trusted root' }
}
if ([bool]$payload.require_service_write -and -not $serviceWriteOnTarget) { throw 'service write ACE missing' }
[pscustomobject]@{ ok = $true } | ConvertTo-Json -Compress
"""
    result = run_system_powershell_json(
        script,
        {
            "path": path,
            "stop_path": stop_path,
            "service_write_root": service_write_root or "",
            "require_service_write": require_service_write,
        },
    )
    if result.get("ok") is not True:
        raise ToolError("Runner trust path ACL validation failed closed")

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def authenticode_summary(path: str) -> dict[str, str]:
    script = r"""
$ErrorActionPreference = 'Stop'
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$signature = Get-AuthenticodeSignature -LiteralPath ([string]$payload.path)
[pscustomobject]@{
  status = [string]$signature.Status
  certificate_thumbprint = if ($null -eq $signature.SignerCertificate) { '' } else { [string]$signature.SignerCertificate.Thumbprint }
} | ConvertTo-Json -Compress
"""
    result = run_system_powershell_json(script, {"path": path})
    return {
        "status": str(result.get("status") or ""),
        "certificate_thumbprint": re.sub(r"[^0-9A-Fa-f]", "", str(result.get("certificate_thumbprint") or "")).upper(),
    }


def verify_runner_binary(path: Path, expected_sha256: str) -> dict[str, str]:
    if path.name.casefold() != "gitlab-runner.exe" or not path.is_file():
        raise ToolError("Runner policy binary must be an existing gitlab-runner.exe")
    actual_sha256 = sha256_file(path)
    if actual_sha256.casefold() != expected_sha256.casefold():
        raise ToolError("GitLab Runner binary SHA256 does not match the protected policy")
    signature = authenticode_summary(str(path))
    if signature["status"].casefold() != "valid" or not signature["certificate_thumbprint"]:
        raise ToolError("GitLab Runner Authenticode signature is not valid")
    return {
        "sha256": actual_sha256.upper(),
        "signature_thumbprint": signature["certificate_thumbprint"],
    }


RUNNER_SERVICE_ACCOUNT = "NT AUTHORITY\\NetworkService"
RUNNER_CONFIG_FORBIDDEN_FIELDS = frozenset(
    {
        "environment",
        "pre_build_script",
        "post_build_script",
        "pre_get_sources_script",
        "pre_clone_script",
    }
)
RUNNER_JOURNAL_FIELDS = frozenset(
    {
        "schema_version",
        "policy_name",
        "gitlab_url",
        "project_id",
        "runner_id",
        "runner_name",
        "tags",
        "binary_sha256",
        "service_name",
        "service_account",
        "stage",
        "service_state",
    }
)
RUNNER_IDENTITY_FIELDS = frozenset(
    {
        "schema",
        "policy_name",
        "project_id",
        "runner_id",
        "runner_name",
        "tags",
        "binary_sha256",
        "config_sha256",
        "service_name",
        "service_account",
        "machine_identity_sha256",
        "stage",
    }
)


def harden_generated_runner_config(path: Path) -> None:
    script = r"""
$ErrorActionPreference = 'Stop'
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$path = [string]$payload.path
$system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$networkService = New-Object Security.Principal.SecurityIdentifier('S-1-5-20')
$acl = New-Object Security.AccessControl.FileSecurity
$acl.SetOwner($admins)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,'FullControl','Allow')))
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($admins,'FullControl','Allow')))
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($networkService,'ReadAndExecute','Allow')))
Set-Acl -LiteralPath $path -AclObject $acl
[pscustomobject]@{ ok = $true } | ConvertTo-Json -Compress
"""
    result = run_system_powershell_json(script, {"path": str(path)})
    if result.get("ok") is not True:
        raise ToolError("Generated Runner config ACL hardening failed closed")


def verify_runner_config(policy: dict[str, Any], gitlab_url: str) -> None:
    config_path = Path(policy["config_path"])
    try:
        with config_path.open("rb") as stream:
            config = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ToolError("Generated Runner config is unreadable or invalid TOML") from exc
    if config.get("concurrent") != 1:
        raise ToolError("Generated Runner config must set concurrent=1")
    runners = config.get("runners")
    if not isinstance(runners, list) or len(runners) != 1 or not isinstance(runners[0], dict):
        raise ToolError("Generated Runner config must contain exactly one Runner")
    runner = runners[0]
    if RUNNER_CONFIG_FORBIDDEN_FIELDS & set(runner):
        raise ToolError("Generated Runner config contains a forbidden script or environment field")
    token = runner.get("token")
    if not isinstance(token, str) or not token:
        raise ToolError("Generated Runner config has no authentication token")
    if str(runner.get("name") or "") != policy["runner_name"]:
        raise ToolError("Generated Runner config name does not match the protected policy")
    if normalize_base_url(str(runner.get("url") or "")).casefold() != normalize_base_url(gitlab_url).casefold():
        raise ToolError("Generated Runner config URL does not match the protected policy")
    if str(runner.get("executor") or "").casefold() != "shell":
        raise ToolError("Generated Runner config executor must be shell")
    if str(runner.get("shell") or "").casefold() != "powershell":
        raise ToolError("Generated Runner config shell must be powershell")
    expected_paths = {
        "builds_dir": str(policy["builds_dir"]),
        "cache_dir": str(policy["cache_dir"]),
    }
    for field, expected in expected_paths.items():
        actual = canonical_windows_path(runner.get(field), field)
        if ntpath.normcase(actual) != ntpath.normcase(canonical_windows_path(expected, field)):
            raise ToolError(f"Generated Runner config {field} escaped the isolated policy work root")


def harden_runner_journal(path: Path) -> None:
    script = r"""
$ErrorActionPreference = 'Stop'
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$path = [string]$payload.path
$system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$acl = New-Object Security.AccessControl.FileSecurity
$acl.SetOwner($admins)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,'FullControl','Allow')))
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($admins,'FullControl','Allow')))
Set-Acl -LiteralPath $path -AclObject $acl
[pscustomobject]@{ ok = $true } | ConvertTo-Json -Compress
"""
    result = run_system_powershell_json(script, {"path": str(path)})
    if result.get("ok") is not True:
        raise ToolError("Runner provisioning journal ACL hardening failed closed")


def write_runner_journal(
    policy: dict[str, Any],
    runner_id: int,
    project_id: int,
    stage: str,
    service_state: str,
) -> None:
    journal_path = Path(policy["journal_path"])
    temp_path = journal_path.with_name(journal_path.name + ".tmp")
    payload = {
        "schema_version": RUNNER_JOURNAL_SCHEMA_VERSION,
        "policy_name": policy["policy_name"],
        "gitlab_url": policy["gitlab_url"],
        "project_id": project_id,
        "runner_id": runner_id,
        "runner_name": policy["runner_name"],
        "tags": list(policy["tags"]),
        "binary_sha256": policy["binary_sha256"],
        "service_name": policy["service_name"],
        "service_account": policy["service_account"],
        "stage": stage,
        "service_state": service_state,
    }
    try:
        temp_path.write_text(
            json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        harden_runner_journal(temp_path)
        os.replace(temp_path, journal_path)
        harden_runner_journal(journal_path)
        assert_strict_windows_acl(str(journal_path), str(policy["application_root"]))
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise ToolError("Runner provisioning journal update failed closed") from None


def load_runner_journal(policy: dict[str, Any]) -> dict[str, Any]:
    journal_path = Path(policy["journal_path"])
    if not journal_path.is_file():
        raise ToolError("No protected Runner provisioning journal exists for this policy")
    assert_strict_windows_acl(str(journal_path), str(policy["application_root"]))
    try:
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolError("Protected Runner provisioning journal is unreadable or invalid") from exc
    if not isinstance(journal, dict) or set(journal) != RUNNER_JOURNAL_FIELDS:
        raise ToolError("Protected Runner provisioning journal has an invalid schema")
    bindings_match = (
        journal.get("schema_version") == RUNNER_JOURNAL_SCHEMA_VERSION
        and journal.get("policy_name") == policy["policy_name"]
        and str(journal.get("gitlab_url") or "").casefold() == str(policy["gitlab_url"]).casefold()
        and journal.get("runner_name") == policy["runner_name"]
        and {str(tag).casefold() for tag in journal.get("tags", [])} == {tag.casefold() for tag in policy["tags"]}
        and str(journal.get("binary_sha256") or "").upper() == str(policy["binary_sha256"]).upper()
        and journal.get("service_name") == policy["service_name"]
        and journal.get("service_account") == policy["service_account"]
    )
    if not bindings_match:
        raise ToolError("Protected Runner provisioning journal does not match the current policy")
    try:
        runner_id = int(journal["runner_id"])
        project_id = int(journal["project_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ToolError("Protected Runner provisioning journal ids are invalid") from exc
    if runner_id <= 0 or project_id <= 0:
        raise ToolError("Protected Runner provisioning journal ids are invalid")
    journal["runner_id"] = runner_id
    journal["project_id"] = project_id
    return journal


def machine_identity_sha256(machine_guid: Any) -> str:
    if not isinstance(machine_guid, str) or not machine_guid.strip():
        raise ToolError("Windows MachineGuid is unavailable; Runner identity failed closed")
    normalized = machine_guid.strip().lower()
    material = (RUNNER_IDENTITY_SCHEMA + "\0" + normalized).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def windows_machine_identity_sha256() -> str:
    require_windows_runner_host()
    try:
        import winreg

        access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            access,
        ) as key:
            machine_guid, _value_type = winreg.QueryValueEx(key, "MachineGuid")
        return machine_identity_sha256(machine_guid)
    except Exception:
        raise ToolError("Windows MachineGuid is unavailable; Runner identity failed closed") from None


def assert_runner_identity_receipt_acl(path: Path) -> None:
    script = r"""
$ErrorActionPreference = 'Stop'
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$acl = Get-Acl -LiteralPath ([string]$payload.path)
$admins = 'S-1-5-32-544'
$ownerSid = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
if ($ownerSid -ne $admins) { throw 'identity receipt owner rejected' }
if (-not $acl.AreAccessRulesProtected) { throw 'identity receipt inheritance rejected' }
$networkService = New-Object Security.Principal.SecurityIdentifier('S-1-5-20')
$networkReadRule = New-Object Security.AccessControl.FileSystemAccessRule($networkService,'ReadAndExecute','Allow')
$expected = @{
  'S-1-5-18' = [int][Security.AccessControl.FileSystemRights]::FullControl
  'S-1-5-32-544' = [int][Security.AccessControl.FileSystemRights]::FullControl
  'S-1-5-20' = [int]$networkReadRule.FileSystemRights
}
$rules = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
if ($rules.Count -ne 3) { throw 'identity receipt ACE count rejected' }
foreach ($rule in $rules) {
  $sid = $rule.IdentityReference.Value
  if ($rule.IsInherited -or
      $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
      -not $expected.ContainsKey($sid) -or
      [int]$rule.FileSystemRights -ne $expected[$sid]) {
    throw 'identity receipt ACE rejected'
  }
  $expected.Remove($sid)
}
if ($expected.Count -ne 0) { throw 'identity receipt required ACE missing' }
[pscustomobject]@{ ok = $true } | ConvertTo-Json -Compress
"""
    result = run_system_powershell_json(script, {"path": str(path)})
    if result.get("ok") is not True:
        raise ToolError("Runner identity receipt ACL validation failed closed")


def harden_runner_identity_receipt(path: Path) -> None:
    script = r"""
$ErrorActionPreference = 'Stop'
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$path = [string]$payload.path
$system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$networkService = New-Object Security.Principal.SecurityIdentifier('S-1-5-20')
$acl = New-Object Security.AccessControl.FileSecurity
$acl.SetOwner($admins)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,'FullControl','Allow')))
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($admins,'FullControl','Allow')))
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($networkService,'ReadAndExecute','Allow')))
Set-Acl -LiteralPath $path -AclObject $acl
[pscustomobject]@{ ok = $true } | ConvertTo-Json -Compress
"""
    result = run_system_powershell_json(script, {"path": str(path)})
    if result.get("ok") is not True:
        raise ToolError("Runner identity receipt ACL hardening failed closed")
    assert_runner_identity_receipt_acl(path)


def build_runner_identity_receipt(
    policy: dict[str, Any], runner_id: int, project_id: int
) -> dict[str, Any]:
    if (
        type(runner_id) is not int
        or runner_id <= 0
        or type(project_id) is not int
        or project_id <= 0
    ):
        raise ToolError("Runner identity receipt ids are invalid")
    if not policy.get("install_service") or policy.get("service_account") != "NetworkService":
        raise ToolError("Runner identity receipt requires the protected NetworkService policy")
    binary_path = Path(policy["binary_path"])
    config_path = Path(policy["config_path"])
    identity_path = Path(policy["identity_path"])
    if (
        config_path.name.casefold() != "config.toml"
        or identity_path.name.casefold() != RUNNER_IDENTITY_FILE_NAME
        or config_path.parent != identity_path.parent
    ):
        raise ToolError("Runner identity receipt and config paths escaped the fixed runtime root")
    assert_strict_windows_acl(str(config_path), str(policy["application_root"]))
    verify_runner_config(policy, str(policy["gitlab_url"]))
    binary_sha256 = sha256_file(binary_path).lower()
    if binary_sha256 != str(policy["binary_sha256"]).lower():
        raise ToolError("GitLab Runner binary changed before identity receipt creation")
    config_sha256 = sha256_file(config_path).lower()
    machine_sha256 = windows_machine_identity_sha256().lower()
    if not SHA256_PATTERN.fullmatch(machine_sha256):
        raise ToolError("Windows machine identity digest is invalid")
    return {
        "schema": RUNNER_IDENTITY_SCHEMA,
        "policy_name": policy["policy_name"],
        "project_id": project_id,
        "runner_id": runner_id,
        "runner_name": policy["runner_name"],
        "tags": sorted(policy["tags"], key=str.casefold),
        "binary_sha256": binary_sha256,
        "config_sha256": config_sha256,
        "service_name": policy["service_name"],
        "service_account": "NetworkService",
        "machine_identity_sha256": machine_sha256,
        "stage": "ready",
    }


def load_runner_identity_receipt(policy: dict[str, Any]) -> dict[str, Any]:
    identity_path = Path(policy["identity_path"])
    if not identity_path.is_file():
        raise ToolError("Protected Runner identity receipt is missing")
    assert_runner_identity_receipt_acl(identity_path)
    assert_strict_windows_acl(str(identity_path), str(policy["application_root"]))
    try:
        receipt = json.loads(identity_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolError("Protected Runner identity receipt is unreadable or invalid") from exc
    if not isinstance(receipt, dict) or set(receipt) != RUNNER_IDENTITY_FIELDS:
        raise ToolError("Protected Runner identity receipt has an invalid schema")
    runner_id = receipt.get("runner_id")
    project_id = receipt.get("project_id")
    if type(runner_id) is not int or runner_id <= 0 or type(project_id) is not int or project_id <= 0:
        raise ToolError("Protected Runner identity receipt ids are invalid")
    expected = build_runner_identity_receipt(policy, runner_id, project_id)
    if receipt != expected:
        raise ToolError("Protected Runner identity receipt does not match current attested state")
    return receipt


def write_runner_identity_receipt(
    policy: dict[str, Any], runner_id: int, project_id: int
) -> dict[str, Any]:
    identity_path = Path(policy["identity_path"])
    temp_path = identity_path.with_name(identity_path.name + ".tmp")
    payload = build_runner_identity_receipt(policy, runner_id, project_id)
    try:
        temp_path.write_text(
            json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        harden_runner_identity_receipt(temp_path)
        os.replace(temp_path, identity_path)
        harden_runner_identity_receipt(identity_path)
        receipt = load_runner_identity_receipt(policy)
        if receipt != payload:
            raise ToolError("Protected Runner identity receipt did not verify exactly")
        return receipt
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
            identity_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise ToolError("Runner identity receipt update failed closed") from None


def windows_service_record(service_name: str) -> dict[str, Any]:
    if not RUNNER_SERVICE_NAME_PATTERN.fullmatch(service_name):
        raise ToolError("Protected Runner service_name is invalid")
    script = r"""
$ErrorActionPreference = 'Stop'
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$escaped = ([string]$payload.service_name).Replace("'", "''")
$service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $escaped + "'")
if ($null -eq $service) {
  [pscustomobject]@{ exists = $false; state = ''; start_name = ''; path_name = ''; dacl_safe = $false } | ConvertTo-Json -Compress
} else {
  $allowedControllers = @('S-1-5-18','S-1-5-32-544')
  try {
    $trustedInstaller = (New-Object Security.Principal.NTAccount('NT SERVICE','TrustedInstaller')).Translate([Security.Principal.SecurityIdentifier]).Value
    $allowedControllers += $trustedInstaller
  } catch {}
  $daclSafe = $false
  try {
    $scPath = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
    if (-not (Test-Path -LiteralPath $scPath -PathType Leaf)) { throw 'trusted sc.exe unavailable' }
    $lines = & $scPath sdshow ([string]$payload.service_name) 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'service descriptor query failed' }
    $sddl = $lines | Where-Object { [string]$_ -match '^(O:|G:|D:|S:)' } | Select-Object -Last 1
    if ([string]::IsNullOrWhiteSpace([string]$sddl)) { throw 'service descriptor missing' }
    $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor([string]$sddl, 0)
    $daclProtected = ($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0
    $daclSafe = $null -ne $descriptor.DiscretionaryAcl -and $daclProtected
    $dangerous = 0x00000002 -bor 0x00000010 -bor 0x00000020 -bor 0x00000040 -bor
      0x00000100 -bor 0x00010000 -bor 0x00040000 -bor 0x00080000 -bor
      0x10000000 -bor 0x20000000 -bor 0x40000000
    if ($daclSafe) {
      foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace -is [Security.AccessControl.QualifiedAce] -and
            $ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and
            (($ace.AccessMask -band $dangerous) -ne 0) -and
            $allowedControllers -notcontains $ace.SecurityIdentifier.Value) {
          $daclSafe = $false
          break
        }
      }
    }
  } catch {
    $daclSafe = $false
  }
  [pscustomobject]@{
    exists = $true
    state = [string]$service.State
    start_name = [string]$service.StartName
    path_name = [string]$service.PathName
    dacl_safe = [bool]$daclSafe
  } | ConvertTo-Json -Compress
}
"""
    return run_system_powershell_json(script, {"service_name": service_name})


def harden_windows_service_dacl(policy: dict[str, Any]) -> None:
    script = r"""
$ErrorActionPreference = 'Stop'
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$scPath = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
if (-not (Test-Path -LiteralPath $scPath -PathType Leaf)) { throw 'trusted sc.exe unavailable' }
$sddl = 'D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)'
$null = & $scPath sdset ([string]$payload.service_name) $sddl 2>$null
if ($LASTEXITCODE -ne 0) { throw 'service descriptor update failed' }
[pscustomobject]@{ ok = $true } | ConvertTo-Json -Compress
"""
    result = run_system_powershell_json(script, {"service_name": str(policy["service_name"])})
    if result.get("ok") is not True:
        raise ToolError("Dedicated Windows Runner service DACL hardening failed closed")


def configure_windows_service_network_service(policy: dict[str, Any]) -> None:
    script = r"""
$ErrorActionPreference = 'Stop'
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$escaped = ([string]$payload.service_name).Replace("'", "''")
$service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $escaped + "'")
if ($null -eq $service) { throw 'service does not exist' }
if (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]$service.State, 'Stopped')) {
  throw 'service must be stopped before account transition'
}
$result = Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{
  StartName = 'NT AUTHORITY\NetworkService'
}
[pscustomobject]@{ return_value = [int]$result.ReturnValue } | ConvertTo-Json -Compress
"""
    result = run_system_powershell_json(script, {"service_name": str(policy["service_name"])})
    if result.get("return_value") != 0:
        raise ToolError("Dedicated Windows Runner service account transition failed closed")


def disable_windows_service(policy: dict[str, Any]) -> bool:
    script = r"""
$ErrorActionPreference = 'Stop'
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$escaped = ([string]$payload.service_name).Replace("'", "''")
$service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $escaped + "'")
if ($null -eq $service) {
  [pscustomobject]@{ disabled = $true } | ConvertTo-Json -Compress
  exit 0
}
if (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]$service.State, 'Stopped')) {
  $null = Invoke-CimMethod -InputObject $service -MethodName StopService
}
$result = Invoke-CimMethod -InputObject $service -MethodName ChangeStartMode -Arguments @{ StartMode = 'Disabled' }
[pscustomobject]@{ disabled = ([int]$result.ReturnValue -eq 0) } | ConvertTo-Json -Compress
"""
    try:
        result = run_system_powershell_json(script, {"service_name": str(policy["service_name"])})
        return result.get("disabled") is True
    except Exception:
        return False


def normalized_service_account(value: Any) -> str:
    return re.sub(r"[ .\\/_-]+", "", str(value or "")).casefold()


def windows_command_line_argv(command_line: str) -> list[str]:
    if os.name != "nt":
        raise ToolError("Windows service command-line parsing is unavailable")
    import ctypes

    argc = ctypes.c_int()
    command_line_to_argv = ctypes.windll.shell32.CommandLineToArgvW
    command_line_to_argv.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
    command_line_to_argv.restype = ctypes.POINTER(ctypes.c_wchar_p)
    pointer = command_line_to_argv(command_line, ctypes.byref(argc))
    if not pointer:
        raise ToolError("Dedicated Windows Runner service command line is invalid")
    try:
        return [pointer[index] for index in range(argc.value)]
    finally:
        ctypes.windll.kernel32.LocalFree(pointer)


def attest_windows_service_image(policy: dict[str, Any], record: Any) -> None:
    if not isinstance(record, dict) or record.get("exists") is not True:
        raise ToolError("Dedicated Windows Runner service does not exist")
    command_line = str(record.get("path_name") or "").strip()
    argv = windows_command_line_argv(command_line)
    if len(argv) < 2 or argv[1].casefold() != "run":
        raise ToolError("Dedicated Windows Runner service command line has unexpected arguments")
    if ntpath.normcase(ntpath.normpath(argv[0])) != ntpath.normcase(ntpath.normpath(str(policy["binary_path"]))):
        raise ToolError("Dedicated Windows Runner service executable does not match the protected policy")

    arguments = argv[2:]
    has_syslog = bool(arguments and arguments[-1].casefold() == "--syslog")
    if has_syslog:
        arguments = arguments[:-1]
    if len(arguments) % 2 != 0:
        raise ToolError("Dedicated Windows Runner service command line has unexpected arguments")
    argument_pairs = list(zip(arguments[::2], arguments[1::2]))
    if len({flag.casefold() for flag, _value in argument_pairs}) != len(argument_pairs):
        raise ToolError("Dedicated Windows Runner service command line contains duplicate arguments")
    actual = {flag.casefold(): value for flag, value in argument_pairs}
    layout = (frozenset(actual), has_syslog)
    supported_layouts = {
        (frozenset({"--config", "--service"}), True),
        (frozenset({"--working-directory", "--config", "--service"}), False),
    }
    if layout not in supported_layouts:
        raise ToolError("Dedicated Windows Runner service command line has unexpected arguments")

    expected_paths = {"--config": str(policy["config_path"])}
    if "--working-directory" in actual:
        expected_paths["--working-directory"] = str(policy["working_dir"])
    for flag, expected in expected_paths.items():
        if ntpath.normcase(ntpath.normpath(actual[flag])) != ntpath.normcase(ntpath.normpath(expected)):
            raise ToolError("Dedicated Windows Runner service command line does not match the protected policy")
    if actual["--service"].casefold() != str(policy["service_name"]).casefold():
        raise ToolError("Dedicated Windows Runner service command line does not match the protected policy")


def attest_windows_service_command(policy: dict[str, Any], record: Any) -> None:
    attest_windows_service_image(policy, record)
    if record.get("dacl_safe") is not True:
        raise ToolError("Dedicated Windows Runner service security descriptor is not trusted")


def attest_windows_service(policy: dict[str, Any], record: Any, *, require_running: bool) -> None:
    attest_windows_service_command(policy, record)
    if normalized_service_account(record.get("start_name")) != normalized_service_account(RUNNER_SERVICE_ACCOUNT):
        raise ToolError("Dedicated Windows Runner service LogOnAs is not NetworkService")
    if require_running and str(record.get("state") or "").casefold() != "running":
        raise ToolError("Dedicated Windows Runner service is not Running")


def wait_for_runner_online(
    gl: GitLabClient,
    policy: dict[str, Any],
    runner_id: int,
    project_id: int,
) -> bool:
    deadline = time.monotonic() + int(policy["timeout_seconds"])
    while True:
        try:
            service = windows_service_record(str(policy["service_name"]))
            attest_windows_service(policy, service, require_running=True)
            record = gl.request("GET", f"/runners/{runner_id}")
            attest_runner_record(record, policy, runner_id, project_id, paused=True)
            if str(record.get("status") or "").casefold() == "online":
                return True
        except ToolError:
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(2)


def cleanup_partial_service(policy: dict[str, Any]) -> bool:
    try:
        if windows_service_record(str(policy["service_name"])).get("exists") is not True:
            return True
    except Exception:
        return False
    for command, stage in (("stop", "partial service stop"), ("uninstall", "partial service uninstall")):
        try:
            run_gitlab_runner_process(
                policy,
                [command, "--service", policy["service_name"]],
                stage,
            )
        except Exception:
            pass
    try:
        if windows_service_record(str(policy["service_name"])).get("exists") is False:
            return True
    except Exception:
        return False
    disable_windows_service(policy)
    return False

def load_windows_runner_policy(
    policy_name: Any,
    *,
    allow_existing_registration: bool = False,
) -> dict[str, Any]:
    require_windows_runner_host()
    name = str(policy_name or "").strip()
    if not RUNNER_POLICY_NAME_PATTERN.fullmatch(name):
        raise ToolError("policy_name must use 1-64 lowercase letters, digits, dots, underscores, or hyphens")
    roots = windows_platform_roots()
    program_data = canonical_windows_path(roots["program_data"], "program_data")
    program_files = [canonical_windows_path(roots["program_files"], "program_files")]
    if roots.get("program_files_x86"):
        program_files.append(canonical_windows_path(roots["program_files_x86"], "program_files_x86"))

    application_root = ntpath.join(program_data, "CodexGitLab")
    policy_root = ntpath.join(application_root, RUNNER_POLICY_DIRECTORY_NAME)
    policy_path = ntpath.join(policy_root, f"{name}.json")
    runtime_root = ntpath.join(application_root, RUNNER_RUNTIME_DIRECTORY_NAME, name)
    working_dir = ntpath.join(runtime_root, "work")
    builds_dir = ntpath.join(working_dir, "builds")
    cache_dir = ntpath.join(working_dir, "cache")
    config_path = ntpath.join(runtime_root, "config.toml")
    journal_path = ntpath.join(runtime_root, RUNNER_JOURNAL_FILE_NAME)
    identity_path = ntpath.join(runtime_root, RUNNER_IDENTITY_FILE_NAME)
    for required_path in (
        application_root,
        policy_root,
        policy_path,
        runtime_root,
        working_dir,
        builds_dir,
        cache_dir,
    ):
        if not Path(required_path).exists():
            raise ToolError("Protected Runner policy/runtime layout is incomplete under ProgramData")
    if not allow_existing_registration and (
        Path(config_path).exists()
        or Path(journal_path).exists()
        or Path(identity_path).exists()
    ):
        raise ToolError("Dedicated Runner state already exists; use the policy-bound resume tool")
    if allow_existing_registration and not Path(journal_path).is_file():
        raise ToolError("No protected Runner journal exists; a fresh atomic provisioning request is required")
    assert_strict_windows_acl(policy_path, application_root)
    assert_strict_windows_acl(runtime_root, application_root)
    for writable_path in (working_dir, builds_dir, cache_dir):
        assert_strict_windows_acl(
            writable_path,
            application_root,
            service_write_root=working_dir,
            require_service_write=True,
        )

    try:
        raw_policy = json.loads(Path(policy_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolError("Protected Runner policy is unreadable or invalid JSON") from exc
    if not isinstance(raw_policy, dict) or set(raw_policy) - RUNNER_POLICY_ALLOWED_FIELDS:
        raise ToolError("Protected Runner policy contains unsupported fields")
    required = {
        "schema_version",
        "gitlab_url",
        "project",
        "runner_name",
        "tag_list",
        "runner_binary",
        "runner_binary_sha256",
        "install_service",
    }
    if required - set(raw_policy):
        raise ToolError("Protected Runner policy is missing required fields")
    if raw_policy.get("schema_version") != RUNNER_POLICY_SCHEMA_VERSION:
        raise ToolError("Unsupported protected Runner policy schema_version")

    runner_name = str(raw_policy.get("runner_name") or "").strip()
    if not runner_name or len(runner_name) > 255 or any(character in runner_name for character in ("\r", "\n", "\0")):
        raise ToolError("Runner policy runner_name is invalid")
    tags_value = raw_policy.get("tag_list")
    if not isinstance(tags_value, list) or not tags_value:
        raise ToolError("Runner policy tag_list must be a nonempty explicit array")
    tags = [str(tag).strip() for tag in tags_value]
    if any(not RUNNER_TAG_PATTERN.fullmatch(tag) for tag in tags):
        raise ToolError("Runner policy contains an invalid tag")
    if len({tag.casefold() for tag in tags}) != len(tags):
        raise ToolError("Runner policy tag_list contains duplicates")

    runner_binary_text = canonical_windows_path(raw_policy.get("runner_binary"), "runner_binary")
    matching_root = next((root for root in program_files if windows_path_is_within(runner_binary_text, root)), None)
    if matching_root is None:
        raise ToolError("Runner binary must be installed under a Windows Program Files root")
    expected_sha256 = str(raw_policy.get("runner_binary_sha256") or "")
    if not SHA256_PATTERN.fullmatch(expected_sha256):
        raise ToolError("Runner policy runner_binary_sha256 must be exactly 64 hexadecimal characters")
    assert_strict_windows_acl(runner_binary_text, matching_root)
    binary_evidence = verify_runner_binary(Path(runner_binary_text), expected_sha256)

    install_service = raw_policy.get("install_service")
    if not isinstance(install_service, bool):
        raise ToolError("Runner policy install_service must be boolean")
    service_name = str(raw_policy.get("service_name") or "").strip()
    service_account = str(raw_policy.get("service_account") or "").strip()
    if install_service:
        if not RUNNER_SERVICE_NAME_PATTERN.fullmatch(service_name) or service_name.casefold() == "gitlab-runner":
            raise ToolError("A dedicated non-default service_name is required when install_service is true")
        if service_account != "NetworkService":
            raise ToolError("Runner policy service_account must be exactly NetworkService")
    elif service_name or service_account:
        raise ToolError("service_name and service_account are only allowed when install_service is true")
    try:
        timeout_seconds = int(raw_policy.get("timeout_seconds") or 120)
    except (TypeError, ValueError) as exc:
        raise ToolError("Runner policy timeout_seconds must be an integer") from exc
    if not 30 <= timeout_seconds <= 600:
        raise ToolError("Runner policy timeout_seconds must be between 30 and 600")

    project = raw_policy.get("project")
    if isinstance(project, int):
        if project <= 0:
            raise ToolError("Runner policy project id must be positive")
    elif not str(project or "").strip():
        raise ToolError("Runner policy project is required")
    return {
        "policy_name": name,
        "gitlab_url": normalize_base_url(str(raw_policy["gitlab_url"])),
        "project": project,
        "runner_name": runner_name,
        "tags": tags,
        "binary_path": Path(runner_binary_text),
        "binary_sha256": binary_evidence["sha256"],
        "binary_signature_thumbprint": binary_evidence["signature_thumbprint"],
        "config_path": Path(config_path),
        "journal_path": Path(journal_path),
        "identity_path": Path(identity_path),
        "working_dir": Path(working_dir),
        "builds_dir": Path(builds_dir),
        "cache_dir": Path(cache_dir),
        "application_root": application_root,
        "install_service": install_service,
        "service_name": service_name,
        "service_account": service_account,
        "timeout_seconds": timeout_seconds,
    }

def run_gitlab_runner_process(
    policy: dict[str, Any],
    arguments: list[str],
    stage: str,
    *,
    registration_token: str | None = None,
) -> None:
    binary_path = Path(policy["binary_path"])
    if sha256_file(binary_path).upper() != str(policy["binary_sha256"]).upper():
        raise ToolError("GitLab Runner binary changed after policy validation")
    command = [str(binary_path), *arguments]
    child_env = runner_child_environment(
        {"CI_SERVER_TOKEN": registration_token} if registration_token else None
    )
    try:
        completed = subprocess.run(
            command,
            cwd=str(policy["working_dir"]),
            env=child_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            timeout=int(policy["timeout_seconds"]),
            check=False,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        raise ToolError(f"GitLab Runner {stage} process failed closed; details suppressed") from None
    finally:
        child_env.pop("CI_SERVER_TOKEN", None)
    if completed.returncode != 0:
        raise ToolError(f"GitLab Runner {stage} failed closed; child output suppressed")


def extract_runner_tags(record: dict[str, Any]) -> list[str]:
    tags_value = record.get("tag_list") or record.get("tags") or []
    tags: list[str] = []
    if isinstance(tags_value, list):
        for value in tags_value:
            if isinstance(value, dict):
                tags.append(str(value.get("name") or ""))
            else:
                tags.append(str(value))
    return [tag for tag in tags if tag]


def attest_runner_record(
    record: Any,
    policy: dict[str, Any],
    runner_id: int,
    project_id: int,
    *,
    paused: bool,
) -> None:
    if not isinstance(record, dict):
        raise ToolError("GitLab Runner API attestation returned an invalid record")
    projects = record.get("projects")
    project_ids = {
        int(item["id"])
        for item in projects
        if isinstance(projects, list) and isinstance(item, dict) and str(item.get("id") or "").isdigit()
    } if isinstance(projects, list) else set()
    actual_tags = [tag.casefold() for tag in extract_runner_tags(record)]
    expected_tags = [tag.casefold() for tag in policy["tags"]]
    checks = (
        int(record.get("id") or 0) == runner_id,
        str(record.get("description") or "") == policy["runner_name"],
        record.get("paused") is paused,
        record.get("locked") is True,
        record.get("run_untagged") is False,
        str(record.get("access_level") or "") == "ref_protected",
        sorted(actual_tags) == sorted(expected_tags),
        project_id in project_ids,
    )
    if not all(checks):
        raise ToolError("GitLab Runner API attestation failed closed")


def cleanup_runner_file(path: Path) -> bool:
    try:
        if path.exists():
            path.unlink()
        return not path.exists()
    except OSError:
        return False


def rollback_created_runner(gl: GitLabClient, runner_id: int, policy: dict[str, Any]) -> tuple[bool, bool]:
    remote_deleted = False
    try:
        gl.request("DELETE", f"/runners/{runner_id}")
        remote_deleted = True
    except Exception:
        pass
    local_deleted = cleanup_runner_file(Path(policy["config_path"]))
    local_deleted = cleanup_runner_file(Path(policy["journal_path"])) and local_deleted
    local_deleted = cleanup_runner_file(Path(policy["identity_path"])) and local_deleted
    return remote_deleted, local_deleted


def safe_runner_result(
    policy: dict[str, Any], runner_id: int, *, stage: str, paused: bool | None,
    ready: bool, service_state: str, remediation: str | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "runner": {
            "id": runner_id, "name": policy["runner_name"], "tags": list(policy["tags"]),
            "config_path": str(policy["config_path"]), "binary_sha256": policy["binary_sha256"],
            "binary_signature_thumbprint": policy["binary_signature_thumbprint"], "registered": True,
        },
        "stage": stage, "paused": paused, "ready": ready,
        "service": {
            "requested": bool(policy["install_service"]), "name": policy["service_name"] or None,
            "account": "NetworkService" if policy["install_service"] else None, "state": service_state,
        },
    }
    if remediation:
        data["remediation"] = remediation
    return tool_result(data)


def confirm_runner_paused(gl: GitLabClient, policy: dict[str, Any], runner_id: int, project_id: int) -> bool:
    try:
        gl.request("PUT", f"/runners/{runner_id}", body={"paused": True})
        record = gl.request("GET", f"/runners/{runner_id}")
        attest_runner_record(record, policy, runner_id, project_id, paused=True)
        return True
    except Exception:
        return False


def update_journal_best_effort(
    policy: dict[str, Any], runner_id: int, project_id: int, stage: str, service_state: str
) -> bool:
    try:
        write_runner_journal(policy, runner_id, project_id, stage, service_state)
        return True
    except Exception:
        return False


def paused_failure_result(
    gl: GitLabClient, policy: dict[str, Any], runner_id: int, project_id: int, *,
    stage: str, service_state: str, remediation: str,
) -> dict[str, Any]:
    paused_confirmed = confirm_runner_paused(gl, policy, runner_id, project_id)
    if not cleanup_runner_file(Path(policy["identity_path"])):
        remediation += (
            " The stale Runner identity receipt could not be removed; keep the Runner paused."
        )
    if not update_journal_best_effort(policy, runner_id, project_id, stage, service_state):
        remediation += " The protected retry journal could not be updated; retain the Runner paused and repair its ACL first."
    return safe_runner_result(
        policy, runner_id, stage=stage, paused=True if paused_confirmed else None,
        ready=False, service_state=service_state, remediation=remediation,
    )

def activate_registered_runner(
    gl: GitLabClient, policy: dict[str, Any], runner_id: int, project_id: int
) -> dict[str, Any]:
    try:
        service = windows_service_record(str(policy["service_name"]))
    except Exception:
        return paused_failure_result(
            gl, policy, runner_id, project_id,
            stage="service_inspection_failed", service_state="unknown",
            remediation="Keep the Runner paused; repair Windows service inspection and retry with the same policy_name.",
        )
    if service.get("exists") is True:
        try:
            attest_windows_service(policy, service, require_running=False)
        except Exception:
            cleanup_ok = cleanup_partial_service(policy)
            return paused_failure_result(
                gl, policy, runner_id, project_id, stage="partial_service_rejected",
                service_state="removed" if cleanup_ok else "disabled_or_unknown",
                remediation="A partial or mismatched service was rejected. Confirm removal, then retry with the same policy_name.",
            )
    else:
        try:
            run_gitlab_runner_process(
                policy,
                ["install", "--service", policy["service_name"],
                 "--working-directory", str(policy["working_dir"]),
                 "--config", str(policy["config_path"])],
                "service install",
            )
        except Exception:
            cleanup_ok = cleanup_partial_service(policy)
            return paused_failure_result(
                gl, policy, runner_id, project_id, stage="service_install_failed",
                service_state="removed" if cleanup_ok else "partial_disabled_or_unknown",
                remediation="Keep the Runner paused; repair the dedicated service installation, then retry with the same policy_name.",
            )
        try:
            service = windows_service_record(str(policy["service_name"]))
            attest_windows_service_image(policy, service)
            if str(service.get("state") or "").casefold() != "stopped":
                raise ToolError("Newly installed Runner service was not Stopped before account transition")
        except Exception:
            cleanup_ok = cleanup_partial_service(policy)
            return paused_failure_result(
                gl, policy, runner_id, project_id, stage="service_attestation_failed",
                service_state="removed" if cleanup_ok else "partial_disabled_or_unknown",
                remediation="The installed service failed executable/Stopped-state attestation; confirm cleanup and retry with the same policy_name.",
            )
        try:
            harden_windows_service_dacl(policy)
            service = windows_service_record(str(policy["service_name"]))
            attest_windows_service_command(policy, service)
        except Exception:
            cleanup_ok = cleanup_partial_service(policy)
            return paused_failure_result(
                gl, policy, runner_id, project_id, stage="service_dacl_hardening_failed",
                service_state="removed" if cleanup_ok else "partial_disabled_or_unknown",
                remediation="The service DACL could not be hardened and attested; confirm cleanup and retry with the same policy_name.",
            )
        try:
            configure_windows_service_network_service(policy)
            service = windows_service_record(str(policy["service_name"]))
            attest_windows_service(policy, service, require_running=False)
        except Exception:
            cleanup_ok = cleanup_partial_service(policy)
            return paused_failure_result(
                gl, policy, runner_id, project_id, stage="service_account_configuration_failed",
                service_state="removed" if cleanup_ok else "partial_disabled_or_unknown",
                remediation="The service could not be changed to NetworkService and was not activated; confirm cleanup and retry with the same policy_name.",
            )
    update_journal_best_effort(policy, runner_id, project_id, "service_installed", "installed")
    if str(service.get("state") or "").casefold() != "running":
        try:
            run_gitlab_runner_process(policy, ["start", "--service", policy["service_name"]], "service start")
        except Exception:
            try:
                service = windows_service_record(str(policy["service_name"]))
                attest_windows_service(policy, service, require_running=True)
            except Exception:
                return paused_failure_result(
                    gl, policy, runner_id, project_id, stage="service_start_failed",
                    service_state="installed_not_running",
                    remediation="Keep the Runner paused; repair and start the dedicated NetworkService service, then retry with the same policy_name.",
                )

    update_journal_best_effort(policy, runner_id, project_id, "service_started", "running")
    if not wait_for_runner_online(gl, policy, runner_id, project_id):
        return paused_failure_result(
            gl, policy, runner_id, project_id, stage="online_attestation_timeout",
            service_state="running_or_unknown",
            remediation="The service or GitLab Runner did not attest Running/online before timeout; keep it paused and retry after connectivity is repaired.",
        )
    failure_stage = "activation_attestation_failed"
    try:
        service = windows_service_record(str(policy["service_name"]))
        attest_windows_service(policy, service, require_running=True)
        paused_record = gl.request("GET", f"/runners/{runner_id}")
        attest_runner_record(paused_record, policy, runner_id, project_id, paused=True)
        if str(paused_record.get("status") or "").casefold() != "online":
            raise ToolError("Paused Runner did not remain online before identity receipt creation")
        failure_stage = "identity_receipt_failed"
        write_runner_identity_receipt(policy, runner_id, project_id)
        failure_stage = "activation_failed"
        gl.request("PUT", f"/runners/{runner_id}", body={"paused": False})
        activated_record = gl.request("GET", f"/runners/{runner_id}")
        attest_runner_record(activated_record, policy, runner_id, project_id, paused=False)
        if str(activated_record.get("status") or "").casefold() != "online":
            raise ToolError("Activated Runner did not remain online")
        write_runner_journal(policy, runner_id, project_id, "ready", "running")
    except Exception:
        cleanup_runner_file(Path(policy["identity_path"]))
        paused_confirmed = confirm_runner_paused(gl, policy, runner_id, project_id)
        try:
            run_gitlab_runner_process(
                policy, ["stop", "--service", policy["service_name"]],
                "service stop after activation failure",
            )
        except Exception:
            pass
        update_journal_best_effort(policy, runner_id, project_id, failure_stage, "stopped_or_unknown")
        return safe_runner_result(
            policy, runner_id, stage=failure_stage,
            paused=True if paused_confirmed else None, ready=False,
            service_state="stopped_or_unknown",
            remediation="Keep the Runner out of production; confirm it is paused, repair API/service attestation, then retry with the same policy_name.",
        )
    return safe_runner_result(
        policy, runner_id, stage="ready", paused=False, ready=True, service_state="running"
    )

def provision_windows_project_runner(args: dict[str, Any]) -> dict[str, Any]:
    require_windows_runner_administrator()
    policy = load_windows_runner_policy(args.get("policy_name"))
    gl = client(args)
    if gl.base_url.casefold() != str(policy["gitlab_url"]).casefold():
        raise ToolError("The protected Runner policy is bound to a different GitLab origin")
    if policy["install_service"]:
        existing_service = windows_service_record(str(policy["service_name"]))
        if existing_service.get("exists") is True:
            raise ToolError("A service with the protected policy name already exists without resumable state")
    project_record = gl.request("GET", f"/projects/{encode_project(policy['project'])}")
    try:
        project_id = int(project_record["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ToolError("GitLab project id resolution failed closed") from exc
    if project_id <= 0:
        raise ToolError("GitLab project id resolution failed closed")
    creation_body = {
        "runner_type": "project_type", "project_id": project_id,
        "description": policy["runner_name"], "locked": True,
        "run_untagged": False, "access_level": "ref_protected", "paused": True,
        "tag_list": list(policy["tags"]),
    }
    created = gl.request("POST", "/user/runners", body=creation_body)
    runner_id = 0
    registration_token = ""
    if isinstance(created, dict):
        try:
            runner_id = int(created.get("id") or 0)
        except (TypeError, ValueError):
            runner_id = 0
        registration_token = str(created.get("token") or "")
    created = None
    if runner_id <= 0 or not registration_token:
        if runner_id > 0:
            rollback_created_runner(gl, runner_id, policy)
        registration_token = ""
        raise ToolError("GitLab Runner creation returned no usable one-time authentication token")
    try:
        write_runner_journal(policy, runner_id, project_id, "api_created_paused", "not_installed")
    except Exception:
        registration_token = ""
        remote_deleted, local_deleted = rollback_created_runner(gl, runner_id, policy)
        raise ToolError(
            f"Runner journal initialization failed closed; rollback remote_deleted={str(remote_deleted).lower()}, local_deleted={str(local_deleted).lower()}"
        ) from None
    pre_service_stage = "registration"
    try:
        run_gitlab_runner_process(
            policy,
            ["register", "--non-interactive", "--url", gl.base_url,
             "--name", policy["runner_name"], "--executor", "shell", "--shell", "powershell",
             "--builds-dir", str(policy["builds_dir"]), "--cache-dir", str(policy["cache_dir"]),
             "--config", str(policy["config_path"])],
            "register", registration_token=registration_token,
        )

        registration_token = ""
        pre_service_stage = "local config validation"
        config_path = Path(policy["config_path"])
        if not config_path.is_file():
            raise ToolError("GitLab Runner register did not create the dedicated config")
        harden_generated_runner_config(config_path)
        assert_strict_windows_acl(str(config_path), str(policy["application_root"]))
        verify_runner_config(policy, gl.base_url)
        pre_service_stage = "verify"
        run_gitlab_runner_process(
            policy, ["verify", "--config", str(config_path), "--name", policy["runner_name"]],
            "verify",
        )
        pre_service_stage = "API attestation"
        record = gl.request("GET", f"/runners/{runner_id}")
        attest_runner_record(record, policy, runner_id, project_id, paused=True)
        write_runner_journal(policy, runner_id, project_id, "registered_paused", "not_installed")
    except Exception:
        registration_token = ""
        remote_deleted, local_deleted = rollback_created_runner(gl, runner_id, policy)
        if remote_deleted and local_deleted:
            raise ToolError(f"GitLab Runner {pre_service_stage} failed closed; atomic rollback succeeded") from None
        raise ToolError(
            f"GitLab Runner {pre_service_stage} failed closed; rollback incomplete for runner id {runner_id}; "
            f"remote_deleted={str(remote_deleted).lower()}, local_deleted={str(local_deleted).lower()}"
        ) from None
    finally:
        registration_token = ""
    if not policy["install_service"]:
        return safe_runner_result(
            policy, runner_id, stage="registered_paused", paused=True, ready=False,
            service_state="not_requested",
            remediation="Install and attest a dedicated NetworkService service before activating this paused Runner.",
        )
    return activate_registered_runner(gl, policy, runner_id, project_id)

def resume_windows_project_runner(args: dict[str, Any]) -> dict[str, Any]:
    require_windows_runner_administrator()
    policy = load_windows_runner_policy(args.get("policy_name"), allow_existing_registration=True)
    gl = client(args)
    if gl.base_url.casefold() != str(policy["gitlab_url"]).casefold():
        raise ToolError("The protected Runner policy is bound to a different GitLab origin")
    journal = load_runner_journal(policy)
    runner_id = int(journal["runner_id"])
    project_id = int(journal["project_id"])
    if not confirm_runner_paused(gl, policy, runner_id, project_id):
        return safe_runner_result(
            policy, runner_id, stage="resume_pause_unconfirmed", paused=None, ready=False,
            service_state=str(journal.get("service_state") or "unknown"),
            remediation="Do not use this Runner until GitLab confirms paused=true.",
        )
    if not cleanup_runner_file(Path(policy["identity_path"])):
        return paused_failure_result(
            gl, policy, runner_id, project_id,
            stage="resume_identity_receipt_reset_failed",
            service_state=str(journal.get("service_state") or "unknown"),
            remediation="The prior Runner identity receipt could not be revoked; keep the Runner paused.",
        )
    project_record = gl.request("GET", f"/projects/{encode_project(policy['project'])}")
    if int(project_record.get("id") or 0) != project_id:
        raise ToolError("Protected Runner journal project id no longer matches GitLab")
    config_path = Path(policy["config_path"])
    if not config_path.is_file():
        remote_deleted, local_deleted = rollback_created_runner(gl, runner_id, policy)
        raise ToolError(
            f"Interrupted registration had no config and was rolled back; remote_deleted={str(remote_deleted).lower()}, local_deleted={str(local_deleted).lower()}"
        )
    try:
        assert_strict_windows_acl(str(config_path), str(policy["application_root"]))
        verify_runner_config(policy, gl.base_url)
    except Exception:
        return paused_failure_result(
            gl, policy, runner_id, project_id, stage="resume_config_validation_failed",
            service_state=str(journal.get("service_state") or "unknown"),
            remediation="The protected config failed validation; keep the Runner paused, repair it, then retry with the same policy_name.",
        )
    try:
        run_gitlab_runner_process(
            policy, ["verify", "--config", str(config_path), "--name", policy["runner_name"]],
            "resume verify",
        )
    except Exception:
        return paused_failure_result(
            gl, policy, runner_id, project_id, stage="resume_verify_failed",
            service_state=str(journal.get("service_state") or "unknown"),
            remediation="Keep the Runner paused; repair its protected config/connectivity and retry with the same policy_name.",
        )
    try:
        record = gl.request("GET", f"/runners/{runner_id}")
        attest_runner_record(record, policy, runner_id, project_id, paused=True)
    except Exception:
        return paused_failure_result(
            gl, policy, runner_id, project_id, stage="resume_api_attestation_failed",
            service_state=str(journal.get("service_state") or "unknown"),
            remediation="Keep the Runner paused; repair its GitLab binding and retry with the same policy_name.",
        )
    if not policy["install_service"]:
        return safe_runner_result(
            policy, runner_id, stage="registered_paused", paused=True, ready=False,
            service_state="not_requested",
            remediation="Enable a protected NetworkService policy before production activation.",
        )
    return activate_registered_runner(gl, policy, runner_id, project_id)

def fully_unquote_path_segment(segment: str) -> str:
    decoded = segment
    while True:
        previous = decoded
        decoded = unquote(previous)
        if decoded == previous:
            return decoded.casefold()


def is_runner_management_path(path: str) -> bool:
    parsed = urlsplit(str(path or ""))
    decoded_segments = [
        fully_unquote_path_segment(raw_segment)
        for raw_segment in parsed.path.replace("\\", "/").strip("/").split("/")
        if raw_segment
    ]
    canonical_segments: list[str] = []
    for segment in decoded_segments:
        if segment == ".":
            continue
        if segment == "..":
            if canonical_segments:
                canonical_segments.pop()
            continue
        canonical_segments.append(segment)
    decoded_segments = canonical_segments
    if (
        len(decoded_segments) >= 2
        and decoded_segments[0] == "api"
        and re.fullmatch(r"v\d+", decoded_segments[1])
    ):
        decoded_segments = decoded_segments[2:]
    if not decoded_segments:
        return False
    if decoded_segments[0] == "runners":
        return True
    if decoded_segments[:2] == ["user", "runners"]:
        return True
    return (
        len(decoded_segments) >= 3
        and decoded_segments[0] in {"projects", "groups"}
        and decoded_segments[2] == "runners"
    )


def assert_safe_generic_api_operation(method: str, path: str, raw: bool) -> None:
    if raw:
        raise ToolError("Raw GitLab API responses are disabled because opaque bodies cannot be safely redacted")
    verb = str(method or "").upper()
    if verb != "GET" and is_runner_management_path(path):
        raise ToolError(
            "Runner management writes are blocked from the generic API tool; use a policy-bound dedicated tool"
        )


def api_request(args: dict[str, Any]) -> dict[str, Any]:
    method = str(args.get("method") or "GET").upper()
    path = str(args.get("path") or "")
    if not path:
        raise ToolError("path is required")
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ToolError("method must be GET, POST, PUT, PATCH, or DELETE")
    query = args.get("query") if isinstance(args.get("query"), dict) else None
    raw = bool(args.get("raw"))
    assert_safe_generic_api_operation(method, path, raw)
    body = args.get("body")
    return tool_result(client(args).request(method, path, query=query, body=body, raw=False))


COMMON_PROFILE = {
    "profile": {"type": "string", "description": "Optional GitLab profile name from GITLAB_CONFIG."}
}


PROJECT_FIELD = {
    "project": {
        "type": ["string", "integer"],
        "description": "GitLab project id or URL path, for example group/subgroup/repo.",
    }
}


TOOLS: dict[str, dict[str, Any]] = {
    "gitlab_list_profiles": {
        "description": "List configured GitLab profiles without exposing tokens.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": list_profiles,
    },
    "gitlab_test_connection": {
        "description": "Test GitLab authentication and return the current user plus server version.",
        "inputSchema": {"type": "object", "properties": COMMON_PROFILE, "additionalProperties": False},
        "handler": test_connection,
    },
    "gitlab_get_current_user": {
        "description": "Return the authenticated GitLab user.",
        "inputSchema": {"type": "object", "properties": COMMON_PROFILE, "additionalProperties": False},
        "handler": current_user,
    },
    "gitlab_search_projects": {
        "description": "Search visible GitLab projects.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                "search": {"type": "string"},
                "membership": {"type": "boolean"},
                "owned": {"type": "boolean"},
                "visibility": {"type": "string", "enum": ["private", "internal", "public"]},
                "order_by": {"type": "string"},
                "sort": {"type": "string", "enum": ["asc", "desc"]},
                "simple": {"type": "boolean"},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT},
            },
            "additionalProperties": False,
        },
        "handler": search_projects,
    },
    "gitlab_get_project": {
        "description": "Get a GitLab project by id or path.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **PROJECT_FIELD},
            "required": ["project"],
            "additionalProperties": False,
        },
        "handler": get_project,
    },
    "gitlab_list_merge_requests": {
        "description": "List GitLab merge requests globally or for a project.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **PROJECT_FIELD,
                "state": {"type": "string", "enum": ["opened", "closed", "locked", "merged", "all"]},
                "scope": {"type": "string"},
                "author_username": {"type": "string"},
                "reviewer_username": {"type": "string"},
                "assignee_username": {"type": "string"},
                "labels": {"type": ["string", "array"], "items": {"type": "string"}},
                "search": {"type": "string"},
                "target_branch": {"type": "string"},
                "source_branch": {"type": "string"},
                "order_by": {"type": "string"},
                "sort": {"type": "string", "enum": ["asc", "desc"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT},
            },
            "additionalProperties": False,
        },
        "handler": list_merge_requests,
    },
    "gitlab_get_merge_request": {
        "description": "Get one GitLab merge request.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **PROJECT_FIELD, "iid": {"type": "integer"}},
            "required": ["project", "iid"],
            "additionalProperties": False,
        },
        "handler": get_merge_request,
    },
    "gitlab_list_merge_request_changes": {
        "description": "Return changed files for a GitLab merge request.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **PROJECT_FIELD, "iid": {"type": "integer"}},
            "required": ["project", "iid"],
            "additionalProperties": False,
        },
        "handler": list_merge_request_changes,
    },
    "gitlab_list_merge_request_discussions": {
        "description": "List discussions for a GitLab merge request, optionally unresolved only.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **PROJECT_FIELD,
                "iid": {"type": "integer"},
                "unresolved_only": {"type": "boolean"},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT},
            },
            "required": ["project", "iid"],
            "additionalProperties": False,
        },
        "handler": list_merge_request_discussions,
    },
    "gitlab_create_merge_request": {
        "description": "Create a GitLab merge request.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **PROJECT_FIELD,
                "source_branch": {"type": "string"},
                "target_branch": {"type": "string"},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "draft": {"type": "boolean"},
                "remove_source_branch": {"type": "boolean"},
                "squash": {"type": "boolean"},
            },
            "required": ["project", "source_branch", "target_branch", "title"],
            "additionalProperties": False,
        },
        "handler": create_merge_request,
    },
    "gitlab_update_merge_request": {
        "description": "Update a GitLab merge request title, description, labels, reviewers, assignees, branch, or state.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **PROJECT_FIELD,
                "iid": {"type": "integer"},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "state_event": {"type": "string", "enum": ["close", "reopen"]},
                "add_labels": {"type": ["string", "array"], "items": {"type": "string"}},
                "remove_labels": {"type": ["string", "array"], "items": {"type": "string"}},
                "assignee_ids": {"type": ["string", "array"], "items": {"type": "integer"}},
                "reviewer_ids": {"type": ["string", "array"], "items": {"type": "integer"}},
                "target_branch": {"type": "string"},
            },
            "required": ["project", "iid"],
            "additionalProperties": False,
        },
        "handler": update_merge_request,
    },
    "gitlab_comment_on_merge_request": {
        "description": "Add a top-level note to a GitLab merge request.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **PROJECT_FIELD, "iid": {"type": "integer"}, "body": {"type": "string"}},
            "required": ["project", "iid", "body"],
            "additionalProperties": False,
        },
        "handler": comment_on_merge_request,
    },
    "gitlab_approve_merge_request": {
        "description": "Approve a GitLab merge request as the authenticated user.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **PROJECT_FIELD, "iid": {"type": "integer"}, "sha": {"type": "string"}},
            "required": ["project", "iid"],
            "additionalProperties": False,
        },
        "handler": approve_merge_request,
    },
    "gitlab_merge_merge_request": {
        "description": "Merge a GitLab merge request.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **PROJECT_FIELD,
                "iid": {"type": "integer"},
                "sha": {"type": "string"},
                "squash": {"type": "boolean"},
                "should_remove_source_branch": {"type": "boolean"},
                "merge_when_pipeline_succeeds": {"type": "boolean"},
                "merge_commit_message": {"type": "string"},
                "squash_commit_message": {"type": "string"},
            },
            "required": ["project", "iid"],
            "additionalProperties": False,
        },
        "handler": merge_merge_request,
    },
    "gitlab_list_issues": {
        "description": "List GitLab issues globally or for a project.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **PROJECT_FIELD,
                "state": {"type": "string", "enum": ["opened", "closed", "all"]},
                "scope": {"type": "string"},
                "labels": {"type": ["string", "array"], "items": {"type": "string"}},
                "search": {"type": "string"},
                "assignee_username": {"type": "string"},
                "author_username": {"type": "string"},
                "order_by": {"type": "string"},
                "sort": {"type": "string", "enum": ["asc", "desc"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT},
            },
            "additionalProperties": False,
        },
        "handler": list_issues,
    },
    "gitlab_get_issue": {
        "description": "Get one GitLab issue.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **PROJECT_FIELD, "iid": {"type": "integer"}},
            "required": ["project", "iid"],
            "additionalProperties": False,
        },
        "handler": get_issue,
    },
    "gitlab_comment_on_issue": {
        "description": "Add a note to a GitLab issue.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **PROJECT_FIELD, "iid": {"type": "integer"}, "body": {"type": "string"}},
            "required": ["project", "iid", "body"],
            "additionalProperties": False,
        },
        "handler": comment_on_issue,
    },
    "gitlab_list_pipelines": {
        "description": "List GitLab CI pipelines for a project.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **PROJECT_FIELD,
                "ref": {"type": "string"},
                "sha": {"type": "string"},
                "status": {"type": "string"},
                "source": {"type": "string"},
                "order_by": {"type": "string"},
                "sort": {"type": "string", "enum": ["asc", "desc"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT},
            },
            "required": ["project"],
            "additionalProperties": False,
        },
        "handler": list_pipelines,
    },
    "gitlab_get_pipeline": {
        "description": "Get one GitLab CI pipeline.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **PROJECT_FIELD, "pipeline_id": {"type": "integer"}},
            "required": ["project", "pipeline_id"],
            "additionalProperties": False,
        },
        "handler": get_pipeline,
    },
    "gitlab_list_pipeline_jobs": {
        "description": "List jobs for a GitLab CI pipeline.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **PROJECT_FIELD,
                "pipeline_id": {"type": "integer"},
                "scope": {"type": ["string", "array"], "items": {"type": "string"}},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT},
            },
            "required": ["project", "pipeline_id"],
            "additionalProperties": False,
        },
        "handler": list_pipeline_jobs,
    },
    "gitlab_get_repository_file": {
        "description": "Read a file from a GitLab repository at a ref.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **PROJECT_FIELD,
                "file_path": {"type": "string"},
                "ref": {"type": "string"},
                "decode": {"type": "boolean"},
            },
            "required": ["project", "file_path"],
            "additionalProperties": False,
        },
        "handler": get_repository_file,
    },
    "gitlab_provision_windows_project_runner": {
        "description": "Atomically create, register, verify, attest, and optionally activate a dedicated Windows project Runner from a protected ProgramData policy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                "policy_name": {
                    "type": "string",
                    "description": "Protected policy basename under ProgramData\\CodexGitLab\\runner-policies; no path is accepted.",
                },
            },
            "required": ["policy_name"],
            "additionalProperties": False,
        },
        "handler": provision_windows_project_runner,
    },
    "gitlab_resume_windows_project_runner": {
        "description": "Idempotently resume and re-attest a paused Windows project Runner from its protected ProgramData journal.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                "policy_name": {
                    "type": "string",
                    "description": "Protected policy basename with an existing protected provisioning journal; no path is accepted.",
                },
            },
            "required": ["policy_name"],
            "additionalProperties": False,
        },
        "handler": resume_windows_project_runner,
    },
    "gitlab_api_request": {
        "description": "Call an arbitrary GitLab REST API endpoint for unsupported operations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
                "path": {"type": "string", "description": "API path such as /projects/:id/members. /api/v4 is optional."},
                "query": {"type": "object"},
                "body": {"type": "object"},
                "raw": {"type": "boolean", "description": "Reserved; true is rejected because opaque responses cannot be safely redacted."},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "handler": api_request,
    },
}


def handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}

    if request_id is None:
        return None

    try:
        if method == "initialize":
            protocol_version = params.get("protocolVersion") or DEFAULT_PROTOCOL_VERSION
            return response(
                request_id,
                {
                    "protocolVersion": protocol_version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            )
        if method == "ping":
            return response(request_id, {})
        if method == "tools/list":
            tools = [
                {"name": name, "description": spec["description"], "inputSchema": spec["inputSchema"]}
                for name, spec in TOOLS.items()
            ]
            return response(request_id, {"tools": tools})
        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            if tool_name not in TOOLS:
                raise ToolError(f"Unknown tool: {tool_name}")
            handler: Callable[[dict[str, Any]], dict[str, Any]] = TOOLS[tool_name]["handler"]
            return response(request_id, handler(arguments))
        return error_response(request_id, -32601, f"Method not found: {method}")
    except ToolError as exc:
        return response(request_id, error_result(str(exc)))
    except Exception as exc:
        eprint(f"Unexpected {type(exc).__name__}; details suppressed")
        return response(request_id, error_result(f"Unexpected {type(exc).__name__}; details suppressed"))


def response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def send_message(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def run_stdio_server() -> None:
    eprint("GitLab MCP stdio server started")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            send_message(error_response(None, -32700, f"Parse error: {exc}"))
            continue
        result = handle_request(message)
        if result is not None:
            send_message(result)


if __name__ == "__main__":
    run_stdio_server()
