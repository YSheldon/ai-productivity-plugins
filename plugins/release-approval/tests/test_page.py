from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_approval_page import (
    DecisionPageBinding,
    DecisionPageResult,
    ReleaseApprovalPage,
    ReleaseApprovalPageError,
)


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_page_binds_loopback_only_uses_port_zero_and_persists_state_before_browser_open(tmp_path: Path) -> None:
    opened: dict[str, object] = {}
    binding = DecisionPageBinding(
        event_id="rel-2026-07-15-0001",
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
        assert state["event_id"] == "rel-2026-07-15-0001"
        assert state["round_id"] == 1
        assert state["role_id"] == "release-manager"
        assert state["page_html_sha256"] == "sha256:" + "1" * 64
        assert "verified" not in str(opened["url"]).lower()
    finally:
        page.close()


def test_page_rejects_non_loopback_host() -> None:
    binding = DecisionPageBinding(
        event_id="rel-2026-07-15-0001",
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
        event_id="rel-2026-07-15-0001",
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

        valid_form = {
            "event_id": binding.event_id,
            "round_id": str(binding.round_id),
            "role_id": binding.role_id,
            "decision": "APPROVE",
            "comment": "ship it",
            "nonce": page.nonce,
            "page_html_sha256": binding.page_html_sha256,
        }
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
        event_id="rel-2026-07-15-0001",
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
