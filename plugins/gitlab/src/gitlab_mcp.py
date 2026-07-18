from __future__ import annotations

import base64
import json
import os
import re
import ssl
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


SERVER_NAME = "gitlab"
SERVER_VERSION = "0.1.2"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
DEFAULT_GITLAB_URL = "https://gitlab.com"
DEFAULT_TIMEOUT_SECONDS = 30
MAX_LIMIT = 100
REDACTED = "[REDACTED]"
SCHANNEL_HELPER = Path(__file__).resolve().parents[1] / "scripts" / "invoke_schannel.ps1"
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


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: REDACTED if normalized_key(key) in SENSITIVE_RESPONSE_KEYS else redact_sensitive(item)
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


def schannel_request(
    method: str,
    url: str,
    headers: dict[str, str],
    data: bytes | None,
    timeout: int,
) -> tuple[int, dict[str, str], bytes]:
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise ToolError("Windows Schannel fallback is unavailable; request failed closed")
    powershell = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not powershell.is_file() or not SCHANNEL_HELPER.is_file():
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


def api_request(args: dict[str, Any]) -> dict[str, Any]:
    method = str(args.get("method") or "GET").upper()
    path = str(args.get("path") or "")
    if not path:
        raise ToolError("path is required")
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ToolError("method must be GET, POST, PUT, PATCH, or DELETE")
    query = args.get("query") if isinstance(args.get("query"), dict) else None
    body = args.get("body")
    return tool_result(client(args).request(method, path, query=query, body=body, raw=bool(args.get("raw"))))


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
                "raw": {"type": "boolean", "description": "Return base64 body and headers instead of JSON decoding."},
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
