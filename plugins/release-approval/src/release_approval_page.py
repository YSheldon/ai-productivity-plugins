from __future__ import annotations

import base64
import hashlib
import http.server
import ipaddress
import json
import re
import secrets
import threading
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


MAX_POST_BODY_BYTES = 64 * 1024
_ALLOWED_FORM_CONTENT_TYPES = {"application/x-www-form-urlencoded"}
_INVALID_PERCENT_ESCAPE_PATTERN = re.compile(r"%(?![0-9A-Fa-f]{2})")


class ReleaseApprovalPageError(RuntimeError):
    """Raised when the local approval page cannot be created safely."""


@dataclass(frozen=True)
class DecisionPageBinding:
    event_id: str
    round_id: int
    role_id: str
    expires_at: str
    page_html_sha256: str


@dataclass(frozen=True)
class DecisionPageResult:
    status: str
    response_text: str


class ReleaseApprovalPage:
    def __init__(
        self,
        *,
        host: str,
        artifact_dir: str | Path,
        page_title: str,
        page_body_html: str,
        binding: DecisionPageBinding,
        submit_decision: Callable[[dict[str, str]], DecisionPageResult],
        open_browser: Callable[[str], None],
        now_fn: Callable[[], datetime] | None = None,
        token_bytes: Callable[[int], bytes] | None = None,
        server_class: type[http.server.ThreadingHTTPServer] = http.server.ThreadingHTTPServer,
        page_session: object | None = None,
    ) -> None:
        if not self._is_loopback_host(host):
            raise ReleaseApprovalPageError("local approval page must bind loopback only.")
        self.host = host
        self.artifact_dir = Path(artifact_dir)
        self.page_title = page_title
        self.page_body_html = page_body_html
        self.binding = binding
        self.submit_decision = submit_decision
        self.open_browser = open_browser
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self.token_bytes = token_bytes or secrets.token_bytes
        self.server_class = server_class
        self.server: http.server.ThreadingHTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._submission_lock = threading.Lock()
        self._artifact_lock = threading.RLock()
        self.page_html_path = self.artifact_dir / "page.html"
        self.page_state_path = self.artifact_dir / "page-state.json"
        self.browser_events_path = self.artifact_dir / "browser-events.jsonl"
        self._page_session = page_session
        self._nonce_used = False
        self._nonce_reserved = False
        if page_session is None:
            self.url_key = self._random_token(32)
            self.url_key_bytes = self._token_length_bytes(self.url_key)
            self.nonce = self._random_token(32)
            self._write_initial_artifacts()
        else:
            self.url_key = str(getattr(page_session, "url_key"))
            self.url_key_bytes = self._token_length_bytes(self.url_key)
            self.nonce = str(getattr(page_session, "nonce"))
            self.page_html_path = Path(getattr(page_session, "page_html_path"))
            self.page_state_path = Path(getattr(page_session, "page_state_path"))
            self.browser_events_path = Path(getattr(page_session, "browser_events_path"))
            self._load_existing_artifacts()

    @property
    def port(self) -> int:
        if self.server is None:
            return 0
        return int(self.server.server_address[1])

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/{self.url_key}/"

    @classmethod
    def from_page_session(
        cls,
        *,
        host: str,
        artifact_dir: str | Path,
        binding: DecisionPageBinding,
        page_session: object,
        submit_decision: Callable[[dict[str, str]], DecisionPageResult],
        open_browser: Callable[[str], None],
        now_fn: Callable[[], datetime] | None = None,
        token_bytes: Callable[[int], bytes] | None = None,
        server_class: type[http.server.ThreadingHTTPServer] = http.server.ThreadingHTTPServer,
    ) -> "ReleaseApprovalPage":
        return cls(
            host=host,
            artifact_dir=artifact_dir,
            page_title="Release approval",
            page_body_html="",
            binding=binding,
            submit_decision=submit_decision,
            open_browser=open_browser,
            now_fn=now_fn,
            token_bytes=token_bytes,
            server_class=server_class,
            page_session=page_session,
        )

    def start(self) -> None:
        handler = self._handler_class()
        self.server = self.server_class((self.host, 0), handler)
        self._server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._server_thread.start()
        self._append_browser_event("browser_open_requested", {"port": self.port})
        self.open_browser(self.url)

    def close(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self._server_thread is not None:
            self._server_thread.join(timeout=5)
            self._server_thread = None

    def _write_initial_artifacts(self) -> None:
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.page_html_path.write_text(self._persisted_html(), encoding="utf-8")
        self.page_state_path.write_text(
            json.dumps(
                {
                    "event_id": self.binding.event_id,
                    "round_id": self.binding.round_id,
                    "role_id": self.binding.role_id,
                    "expires_at": self.binding.expires_at,
                    "page_html_sha256": self.binding.page_html_sha256,
                    "created_at": self._isoformat(self.now_fn()),
                    "nonce_sha256": self._sha256_prefixed(self.nonce),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        self._append_browser_event("page_created", {"event_id": self.binding.event_id})

    def _load_existing_artifacts(self) -> None:
        artifact_dir = self.artifact_dir.resolve(strict=False)
        session_artifact_dir = Path(getattr(self._page_session, "artifact_dir")).resolve(strict=False)
        if session_artifact_dir != artifact_dir:
            raise ReleaseApprovalPageError("page session artifact binding mismatch.")
        expected_paths = {
            self.page_html_path.resolve(strict=False): (artifact_dir / "page.html").resolve(strict=False),
            self.page_state_path.resolve(strict=False): (artifact_dir / "page-state.json").resolve(strict=False),
            self.browser_events_path.resolve(strict=False): (artifact_dir / "browser-events.jsonl").resolve(strict=False),
        }
        for actual, expected in expected_paths.items():
            if actual != expected:
                raise ReleaseApprovalPageError("page session artifact binding mismatch.")
        if not self.page_html_path.is_file() or not self.page_state_path.is_file() or not self.browser_events_path.is_file():
            raise ReleaseApprovalPageError("page session artifacts are incomplete.")

        persisted_html = self.page_html_path.read_text(encoding="utf-8")
        expected_html_sha256 = str(getattr(self._page_session, "page_html_sha256"))
        if self._sha256_prefixed(persisted_html) != expected_html_sha256 or expected_html_sha256 != self.binding.page_html_sha256:
            raise ReleaseApprovalPageError("page HTML binding mismatch.")
        if "__NONCE__" not in persisted_html or "__PAGE_HTML_SHA256__" not in persisted_html:
            raise ReleaseApprovalPageError("page session HTML template is missing required placeholders.")

        state = json.loads(self.page_state_path.read_text(encoding="utf-8"))
        expected_nonce_sha256 = self._sha256_prefixed(self.nonce)
        if state.get("event_id") != self.binding.event_id:
            raise ReleaseApprovalPageError("event binding mismatch.")
        if state.get("round_id") != self.binding.round_id:
            raise ReleaseApprovalPageError("round binding mismatch.")
        if state.get("role_id") != self.binding.role_id:
            raise ReleaseApprovalPageError("role binding mismatch.")
        if state.get("expires_at") != self.binding.expires_at:
            raise ReleaseApprovalPageError("page session state binding mismatch.")
        if state.get("page_html_sha256") != self.binding.page_html_sha256:
            raise ReleaseApprovalPageError("page HTML binding mismatch.")
        if state.get("nonce_sha256") != expected_nonce_sha256 or expected_nonce_sha256 != str(getattr(self._page_session, "nonce_sha256")):
            raise ReleaseApprovalPageError("nonce mismatch.")
        created_at = getattr(self._page_session, "created_at", None)
        if created_at is not None and state.get("created_at") != created_at:
            raise ReleaseApprovalPageError("page session state binding mismatch.")
        self._nonce_used = "used_at" in state
        self._nonce_reserved = "reserved_at" in state

    def _persisted_html(self) -> str:
        return "\n".join(
            [
                "<!doctype html>",
                "<html>",
                "<head>",
                f"<meta charset=\"utf-8\"><title>{self.page_title}</title>",
                "</head>",
                "<body>",
                f"<h1>{self.page_title}</h1>",
                self.page_body_html,
                "<form method=\"post\">",
                f"<input type=\"hidden\" name=\"event_id\" value=\"{self.binding.event_id}\">",
                f"<input type=\"hidden\" name=\"round_id\" value=\"{self.binding.round_id}\">",
                f"<input type=\"hidden\" name=\"role_id\" value=\"{self.binding.role_id}\">",
                "<input type=\"hidden\" name=\"nonce\" value=\"__NONCE__\">",
                f"<input type=\"hidden\" name=\"page_html_sha256\" value=\"{self.binding.page_html_sha256}\">",
                "<label>Decision <input name=\"decision\"></label>",
                "<label>Comment <textarea name=\"comment\"></textarea></label>",
                "<button type=\"submit\">Submit</button>",
                "</form>",
                "</body>",
                "</html>",
                "",
            ]
        )

    def _served_html(self) -> str:
        return (
            self.page_html_path.read_text(encoding="utf-8")
            .replace("__NONCE__", self.nonce)
            .replace("__PAGE_HTML_SHA256__", self.binding.page_html_sha256)
        )

    def _handler_class(self) -> type[http.server.BaseHTTPRequestHandler]:
        page = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path != f"/{page.url_key}/":
                    self.send_error(404)
                    return
                page._append_browser_event("page_get", {})
                body = page._served_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802
                if self.path != f"/{page.url_key}/":
                    self.send_error(404)
                    return
                try:
                    length = page._require_content_length(self.headers.get("Content-Length"))
                    raw = self.rfile.read(length)
                    normalized = page._parse_post_body(raw, content_type=self.headers.get("Content-Type"))
                    result = page._handle_submission(normalized)
                except ReleaseApprovalPageError as exc:
                    page._send_plain_response(self, page._status_code_for_error(exc), "rejected")
                    page._append_browser_event("page_rejected", {"reason": str(exc)})
                    return
                page._send_plain_response(self, 200, result.response_text)

            def log_message(self, format: str, *args) -> None:  # noqa: A003
                return

        return Handler

    def _parse_post_body(self, raw: bytes, *, content_type: str | None) -> dict[str, str]:
        if content_type is not None:
            normalized_content_type = content_type.split(";", 1)[0].strip().lower()
            if normalized_content_type not in _ALLOWED_FORM_CONTENT_TYPES:
                raise ReleaseApprovalPageError("POST body must use application/x-www-form-urlencoded content type.")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReleaseApprovalPageError("POST body must be valid UTF-8.") from exc
        if _INVALID_PERCENT_ESCAPE_PATTERN.search(text):
            raise ReleaseApprovalPageError("POST body contains invalid percent encoding.")
        try:
            form = urllib.parse.parse_qs(
                text,
                strict_parsing=True,
                encoding="utf-8",
                errors="strict",
            )
        except ValueError as exc:
            raise ReleaseApprovalPageError("POST body must be a valid form payload.") from exc
        return self._normalize_form(form)

    def _normalize_form(self, form: dict[str, list[str]]) -> dict[str, str]:
        allowed = {
            "event_id",
            "round_id",
            "role_id",
            "decision",
            "comment",
            "nonce",
            "page_html_sha256",
        }
        if set(form) != allowed:
            raise ReleaseApprovalPageError("POST must contain exactly the allowed fields.")
        normalized: dict[str, str] = {}
        for key, values in form.items():
            if len(values) != 1:
                raise ReleaseApprovalPageError("POST fields must be single-valued.")
            normalized[key] = values[0]
        return normalized

    def _handle_submission(self, form: dict[str, str]) -> DecisionPageResult:
        self._validate_submission(form)
        self._reserve_nonce()
        try:
            self._append_browser_event("page_post", {"decision": form["decision"]})
            result = self.submit_decision(form)
            if result.response_text not in {"sent", "retry queued", "rejected"}:
                raise ReleaseApprovalPageError("page response must be sent, retry queued, or rejected.")
            if result.status == "sent":
                self._consume_reserved_nonce()
            else:
                self._release_reserved_nonce()
            self._write_sha256sums()
            return result
        except Exception:
            self._release_reserved_nonce()
            raise

    def _validate_submission(self, form: dict[str, str]) -> None:
        if form["event_id"] != self.binding.event_id:
            raise ReleaseApprovalPageError("event binding mismatch.")
        if form["round_id"] != str(self.binding.round_id):
            raise ReleaseApprovalPageError("round binding mismatch.")
        if form["role_id"] != self.binding.role_id:
            raise ReleaseApprovalPageError("role binding mismatch.")
        if form["page_html_sha256"] != self.binding.page_html_sha256:
            raise ReleaseApprovalPageError("page HTML binding mismatch.")
        if form["decision"] not in {"APPROVE", "HOLD", "REJECT"}:
            raise ReleaseApprovalPageError("decision must be APPROVE, HOLD, or REJECT.")
        if self._sha256_prefixed(form["nonce"]) != self._sha256_prefixed(self.nonce):
            raise ReleaseApprovalPageError("nonce mismatch.")
        if self._parse_timestamp(self.binding.expires_at) <= self.now_fn().astimezone(timezone.utc):
            raise ReleaseApprovalPageError("page is expired.")

    def _reserve_nonce(self) -> None:
        with self._submission_lock:
            if self._nonce_used or self._nonce_reserved:
                raise ReleaseApprovalPageError("nonce is single-use.")
            with self._artifact_lock:
                state = json.loads(self.page_state_path.read_text(encoding="utf-8"))
                if "used_at" in state:
                    self._nonce_used = True
                    raise ReleaseApprovalPageError("nonce is single-use.")
                if "reserved_at" in state:
                    self._nonce_reserved = True
                    raise ReleaseApprovalPageError("nonce is single-use.")
                state["reserved_at"] = self._isoformat(self.now_fn())
                self.page_state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
                self._write_sha256sums()
            self._nonce_reserved = True

    def _consume_reserved_nonce(self) -> None:
        with self._submission_lock:
            with self._artifact_lock:
                state = json.loads(self.page_state_path.read_text(encoding="utf-8"))
                state.pop("reserved_at", None)
                state["used_at"] = self._isoformat(self.now_fn())
                self.page_state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
                self._write_sha256sums()
            self._nonce_reserved = False
            self._nonce_used = True

    def _release_reserved_nonce(self) -> None:
        with self._submission_lock:
            if not self._nonce_reserved:
                return
            with self._artifact_lock:
                state = json.loads(self.page_state_path.read_text(encoding="utf-8"))
                if state.pop("reserved_at", None) is not None:
                    self.page_state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
                    self._write_sha256sums()
            self._nonce_reserved = False

    def _append_browser_event(self, event_type: str, payload: dict[str, object]) -> None:
        record = {
            "event_type": event_type,
            "recorded_at": self._isoformat(self.now_fn()),
            "payload": payload,
        }
        with self._artifact_lock:
            with self.browser_events_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record, separators=(",", ":")) + "\n")
            self._write_sha256sums()

    def _write_sha256sums(self) -> None:
        with self._artifact_lock:
            lines: list[str] = []
            for path in sorted(self.artifact_dir.iterdir()):
                if not path.is_file() or path.name in {"SHA256SUMS", "SHA256SUMS.tmp"}:
                    continue
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                lines.append(f"{digest} *{path.name}")
            sums_path = self.artifact_dir / "SHA256SUMS"
            tmp_path = self.artifact_dir / "SHA256SUMS.tmp"
            tmp_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            tmp_path.replace(sums_path)

    @staticmethod
    def _require_content_length(raw_value: str | None) -> int:
        if raw_value is None:
            raise ReleaseApprovalPageError("Content-Length is required.")
        try:
            length = int(raw_value)
        except ValueError as exc:
            raise ReleaseApprovalPageError("Content-Length must be a valid positive integer.") from exc
        if length <= 0:
            raise ReleaseApprovalPageError("Content-Length must be a valid positive integer.")
        if length > MAX_POST_BODY_BYTES:
            raise ReleaseApprovalPageError("Content-Length is too large.")
        return length

    @staticmethod
    def _status_code_for_error(error: ReleaseApprovalPageError) -> int:
        message = str(error)
        if "single-use" in message:
            return 409
        if "Content-Length is required" in message:
            return 411
        if "Content-Length is too large" in message:
            return 413
        return 400

    @staticmethod
    def _send_plain_response(handler: http.server.BaseHTTPRequestHandler, status: int, body_text: str) -> None:
        body = body_text.encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "text/plain; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    @staticmethod
    def _sha256_prefixed(value: str) -> str:
        return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _parse_timestamp(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)

    @staticmethod
    def _isoformat(value: datetime) -> str:
        return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _is_loopback_host(host: str) -> bool:
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def _random_token(self, size: int) -> str:
        return base64.urlsafe_b64encode(self.token_bytes(size)).rstrip(b"=").decode("ascii")

    @staticmethod
    def _token_length_bytes(token: str) -> int:
        padded = token + "=" * (-len(token) % 4)
        return len(base64.urlsafe_b64decode(padded.encode("ascii")))
