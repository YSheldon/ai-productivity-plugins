from __future__ import annotations

import hashlib
import json
import socket
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

import release_approval_page as page_module
from release_approval_page import (
    DecisionPageBinding,
    DecisionPageResult,
    ReleaseApprovalPage,
    ReleaseApprovalPageError,
)


MAX_POST_BODY_BYTES = getattr(page_module, "MAX_POST_BODY_BYTES", 64 * 1024)


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _raw_http_request(port: int, raw_request: bytes) -> tuple[int, str]:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        connection.sendall(raw_request)
        connection.shutdown(socket.SHUT_WR)
        response = b""
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response += chunk
    head = response.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
    status_line = head.splitlines()[0]
    return int(status_line.split()[1]), head


def _assert_sha256sums_current(artifact_dir: Path) -> None:
    sums_path = artifact_dir / "SHA256SUMS"
    lines = [line for line in sums_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    expected_files = sorted(path.name for path in artifact_dir.iterdir() if path.is_file() and path.name != "SHA256SUMS")
    seen_files: list[str] = []
    for line in lines:
        digest, star_name = line.split(" *", 1)
        file_path = artifact_dir / star_name
        seen_files.append(star_name)
        assert hashlib.sha256(file_path.read_bytes()).hexdigest() == digest
    assert sorted(seen_files) == expected_files


def _valid_form(binding: DecisionPageBinding, nonce: str) -> dict[str, str]:
    return {
        "event_id": binding.event_id,
        "round_id": str(binding.round_id),
        "role_id": binding.role_id,
        "decision": "APPROVE",
        "comment": "ship it",
        "nonce": nonce,
        "page_html_sha256": binding.page_html_sha256,
    }


def test_page_binds_loopback_only_uses_port_zero_and_persists_state_before_browser_open(tmp_path: Path) -> None:
    opened: dict[str, object] = {}
    binding = DecisionPageBinding(
        event_id="rel-2026-07-16-0001",
        round_id=1,
        role_id="release-manager",
        expires_at="2099-07-16T00:00:00Z",
        page_html_sha256="sha256:" + "1" * 64,
    )

    def opener(url: str) -> None:
        opened["url"] = url
        page_html = tmp_path / "page.html"
        page_state = tmp_path / "page-state.json"
        assert page_html.exists()
        assert page_state.exists()
        state_text = page_state.read_text(encoding="utf-8")
        assert "nonce_sha256" in state_text
        assert page.nonce not in state_text
        assert "url_key" not in state_text

    page = ReleaseApprovalPage(
        host="127.0.0.1",
        artifact_dir=tmp_path,
        page_title="Release approval",
        page_body_html="<p>approve</p>",
        binding=binding,
        submit_decision=lambda form: DecisionPageResult(status="sent", response_text="sent"),
        open_browser=opener,
    )

    page.start()
    try:
        state = _read_json(tmp_path / "page-state.json")
        assert page.server.server_address[0] == "127.0.0.1"
        assert page.server.server_address[1] > 0
        assert page.url_key_bytes >= 32
        assert state["nonce_sha256"].startswith("sha256:")
        assert state["event_id"] == "rel-2026-07-16-0001"
        assert state["round_id"] == 1
        assert state["role_id"] == "release-manager"
        assert state["page_html_sha256"] == "sha256:" + "1" * 64
        assert "verified" not in str(opened["url"]).lower()
    finally:
        page.close()


def test_page_rejects_non_loopback_host() -> None:
    binding = DecisionPageBinding(
        event_id="rel-2026-07-16-0001",
        round_id=1,
        role_id="release-manager",
        expires_at="2099-07-16T00:00:00Z",
        page_html_sha256="sha256:" + "1" * 64,
    )

    with pytest.raises(ReleaseApprovalPageError, match="loopback"):
        ReleaseApprovalPage(
            host="example.com",
            artifact_dir=Path.cwd(),
            page_title="Release approval",
            page_body_html="<p>approve</p>",
            binding=binding,
            submit_decision=lambda form: DecisionPageResult(status="sent", response_text="sent"),
            open_browser=lambda _url: None,
        )


def test_get_requires_random_url_key_and_post_accepts_only_bound_fields(tmp_path: Path) -> None:
    seen_form: dict[str, str] = {}
    binding = DecisionPageBinding(
        event_id="rel-2026-07-16-0001",
        round_id=1,
        role_id="release-manager",
        expires_at="2099-07-16T00:00:00Z",
        page_html_sha256="sha256:" + "2" * 64,
    )
    page = ReleaseApprovalPage(
        host="127.0.0.1",
        artifact_dir=tmp_path,
        page_title="Release approval",
        page_body_html="<p>approve</p>",
        binding=binding,
        submit_decision=lambda form: seen_form.update(form) or DecisionPageResult(status="sent", response_text="sent"),
        open_browser=lambda _url: None,
    )
    page.start()
    try:
        with pytest.raises(urllib.error.HTTPError) as wrong_key:
            urllib.request.urlopen(f"http://127.0.0.1:{page.port}/wrong/", timeout=5).read()
        assert wrong_key.value.code == 404

        html = urllib.request.urlopen(page.url, timeout=5).read().decode("utf-8")
        assert "Release approval" in html

        valid_form = _valid_form(binding, page.nonce)
        invalid_payload = urllib.parse.urlencode({**valid_form, "decision": "MAYBE"}).encode("utf-8")
        with pytest.raises(urllib.error.HTTPError) as invalid_decision:
            urllib.request.urlopen(page.url, data=invalid_payload, timeout=5).read()
        assert invalid_decision.value.code == 400

        extra_payload = urllib.parse.urlencode({**valid_form, "unexpected": "x"}).encode("utf-8")
        with pytest.raises(urllib.error.HTTPError) as invalid_field:
            urllib.request.urlopen(page.url, data=extra_payload, timeout=5).read()
        assert invalid_field.value.code == 400

        payload = urllib.parse.urlencode(valid_form).encode("utf-8")
        response = urllib.request.urlopen(page.url, data=payload, timeout=5)
        assert response.read().decode("utf-8") == "sent"
        assert seen_form["decision"] == "APPROVE"

        second = urllib.request.Request(page.url, data=payload, method="POST")
        with pytest.raises(urllib.error.HTTPError) as reused:
            urllib.request.urlopen(second, timeout=5).read()
        assert reused.value.code == 409
    finally:
        page.close()


def test_page_response_text_only_reports_sent_retry_or_rejected(tmp_path: Path) -> None:
    binding = DecisionPageBinding(
        event_id="rel-2026-07-16-0001",
        round_id=1,
        role_id="release-manager",
        expires_at="2099-07-16T00:00:00Z",
        page_html_sha256="sha256:" + "3" * 64,
    )

    page = ReleaseApprovalPage(
        host="127.0.0.1",
        artifact_dir=tmp_path,
        page_title="Release approval",
        page_body_html="<p>approve</p>",
        binding=binding,
        submit_decision=lambda _form: DecisionPageResult(status="retry_queued", response_text="retry queued"),
        open_browser=lambda _url: None,
    )
    page.start()
    try:
        payload = urllib.parse.urlencode(
            {
                "event_id": binding.event_id,
                "round_id": str(binding.round_id),
                "role_id": binding.role_id,
                "decision": "HOLD",
                "comment": "need logs",
                "nonce": page.nonce,
                "page_html_sha256": binding.page_html_sha256,
            }
        ).encode("utf-8")
        body = urllib.request.urlopen(page.url, data=payload, timeout=5).read().decode("utf-8")
        assert body == "retry queued"
        assert "verified" not in body.lower()
    finally:
        page.close()


def test_concurrent_valid_posts_accept_exactly_one_and_consume_nonce_even_on_retry(tmp_path: Path) -> None:
    seen_forms: list[dict[str, str]] = []
    binding = DecisionPageBinding(
        event_id="rel-2026-07-16-0001",
        round_id=1,
        role_id="release-manager",
        expires_at="2099-07-16T00:00:00Z",
        page_html_sha256="sha256:" + "4" * 64,
    )
    page = ReleaseApprovalPage(
        host="127.0.0.1",
        artifact_dir=tmp_path,
        page_title="Release approval",
        page_body_html="<p>approve</p>",
        binding=binding,
        submit_decision=lambda form: seen_forms.append(dict(form)) or DecisionPageResult(status="retry_queued", response_text="retry queued"),
        open_browser=lambda _url: None,
    )
    original_validate = page._validate_submission
    barrier = threading.Barrier(2)

    def wrapped_validate(form: dict[str, str]) -> None:
        original_validate(form)
        barrier.wait(timeout=5)

    page._validate_submission = wrapped_validate  # type: ignore[method-assign]
    page.start()
    try:
        payload = urllib.parse.urlencode(_valid_form(binding, page.nonce)).encode("utf-8")

        results: list[tuple[str, object]] = []

        def post_once() -> None:
            try:
                body = urllib.request.urlopen(page.url, data=payload, timeout=5).read().decode("utf-8")
                results.append(("ok", body))
            except urllib.error.HTTPError as exc:
                results.append(("http", exc.code))

        threads = [threading.Thread(target=post_once) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert sorted(results) == [("http", 409), ("ok", "retry queued")]
        assert len(seen_forms) == 1

        page._validate_submission = original_validate  # type: ignore[method-assign]
        second_try = urllib.request.Request(page.url, data=payload, method="POST")
        with pytest.raises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(second_try, timeout=5).read()
        assert rejected.value.code == 409
    finally:
        page.close()


@pytest.mark.parametrize(
    ("raw_request", "expected_status"),
    [
        (
            b"POST /TOKEN/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            411,
        ),
        (
            b"POST /TOKEN/ HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n",
            400,
        ),
        (
            b"POST /TOKEN/ HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: nope\r\n\r\n",
            400,
        ),
        (
            f"POST /TOKEN/ HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {MAX_POST_BODY_BYTES + 1}\r\n\r\n".encode("ascii"),
            413,
        ),
    ],
)
def test_post_rejects_missing_invalid_or_oversized_content_length(
    tmp_path: Path,
    raw_request: bytes,
    expected_status: int,
) -> None:
    assert hasattr(page_module, "MAX_POST_BODY_BYTES")
    binding = DecisionPageBinding(
        event_id="rel-2026-07-16-0001",
        round_id=1,
        role_id="release-manager",
        expires_at="2099-07-16T00:00:00Z",
        page_html_sha256="sha256:" + "5" * 64,
    )
    page = ReleaseApprovalPage(
        host="127.0.0.1",
        artifact_dir=tmp_path,
        page_title="Release approval",
        page_body_html="<p>approve</p>",
        binding=binding,
        submit_decision=lambda _form: DecisionPageResult(status="sent", response_text="sent"),
        open_browser=lambda _url: None,
    )
    page.start()
    try:
        status, _head = _raw_http_request(page.port, raw_request.replace(b"/TOKEN/", f"/{page.url_key}/".encode("ascii")))
        assert status == expected_status
    finally:
        page.close()


@pytest.mark.parametrize(
    "raw_request",
    [
        b"POST /TOKEN/ HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nContent-Length: 7\r\n\r\nignored=1",
        b"POST /TOKEN/ HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 46\r\n\r\nevent_id=x&round_id=1&role_id=x&decision=APPROVE",
        b"POST /TOKEN/ HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\ncomment=%ZZbad",
        b"POST /TOKEN/ HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n\xff",
    ],
)
def test_post_rejects_malformed_body_without_nonce_side_effects(tmp_path: Path, raw_request: bytes) -> None:
    callbacks: list[dict[str, str]] = []
    binding = DecisionPageBinding(
        event_id="rel-2026-07-16-0001",
        round_id=1,
        role_id="release-manager",
        expires_at="2099-07-16T00:00:00Z",
        page_html_sha256="sha256:" + "6" * 64,
    )
    page = ReleaseApprovalPage(
        host="127.0.0.1",
        artifact_dir=tmp_path,
        page_title="Release approval",
        page_body_html="<p>approve</p>",
        binding=binding,
        submit_decision=lambda form: callbacks.append(dict(form)) or DecisionPageResult(status="sent", response_text="sent"),
        open_browser=lambda _url: None,
    )
    page.start()
    try:
        status, _head = _raw_http_request(page.port, raw_request.replace(b"/TOKEN/", f"/{page.url_key}/".encode("ascii")))
        assert status == 400
        assert callbacks == []
        state = _read_json(tmp_path / "page-state.json")
        assert "used_at" not in state

        payload = urllib.parse.urlencode(_valid_form(binding, page.nonce)).encode("utf-8")
        response = urllib.request.urlopen(page.url, data=payload, timeout=5)
        assert response.read().decode("utf-8") == "sent"
        assert len(callbacks) == 1
    finally:
        page.close()


def test_sha256sums_stays_current_after_each_browser_event_append(tmp_path: Path) -> None:
    binding = DecisionPageBinding(
        event_id="rel-2026-07-16-0001",
        round_id=1,
        role_id="release-manager",
        expires_at="2099-07-16T00:00:00Z",
        page_html_sha256="sha256:" + "7" * 64,
    )
    page = ReleaseApprovalPage(
        host="127.0.0.1",
        artifact_dir=tmp_path,
        page_title="Release approval",
        page_body_html="<p>approve</p>",
        binding=binding,
        submit_decision=lambda _form: DecisionPageResult(status="sent", response_text="sent"),
        open_browser=lambda _url: None,
    )
    page.start()
    try:
        _assert_sha256sums_current(tmp_path)
        page._append_browser_event("manual-check", {"step": 1})
        _assert_sha256sums_current(tmp_path)
    finally:
        page.close()
