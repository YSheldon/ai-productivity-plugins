from __future__ import annotations

import sys
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from decision_parser import classify_decision, normalize_reply_text


def test_normalize_reply_text_strips_quoted_english_headers() -> None:
    text = """通过

On Tue, Jul 14, 2026 at 09:00 Release Bot <bot@example.com> wrote:
> 不同意
"""

    assert normalize_reply_text(text) == "通过"


def test_normalize_reply_text_strips_chinese_headers_signature_and_disclaimer() -> None:
    text = """批准

发件人： 发布机器人
发送时间： 2026-07-15 09:00
收件人： security-reviewer@example.com

Best regards,
Alice

This email and any attachments are confidential.
"""

    assert normalize_reply_text(text) == "批准"


@pytest.mark.parametrize(
    ("text", "expected_decision", "expected_ambiguous"),
    [
        ("通过", "APPROVE", False),
        ("不同意，需要补充材料。", "REJECT", False),
        ("原则上同意，但还需评估。", "HOLD", True),
        ("待定，等回归结果。", "HOLD", False),
        ("", "HOLD", True),
        ("改为驳回。", "REJECT", False),
    ],
)
def test_classify_decision_is_deterministic_and_orders_reject_before_hold_before_approve(
    text: str,
    expected_decision: str,
    expected_ambiguous: bool,
) -> None:
    parsed = classify_decision(text)

    assert parsed.decision == expected_decision
    assert parsed.ambiguous is expected_ambiguous


def test_classify_decision_does_not_misread_bu_tong_yi_as_approve() -> None:
    parsed = classify_decision("我不同意这次发布。")

    assert parsed.decision == "REJECT"
    assert "同意" not in parsed.matched_terms["approve"]
