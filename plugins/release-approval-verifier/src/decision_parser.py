from __future__ import annotations

import re
from dataclasses import dataclass


_REPLY_BREAK_PATTERNS = (
    re.compile(r"^\s*on .+ wrote:\s*$", re.IGNORECASE),
    re.compile(r"^\s*-{2,}\s*original message\s*-{2,}\s*$", re.IGNORECASE),
    re.compile(r"^\s*(from|sent|to|subject|cc)\s*:\s*", re.IGNORECASE),
    re.compile(r"^\s*(发件人|发送时间|收件人|主题|抄送)\s*[：:]\s*"),
    re.compile(r"^\s*在.+写道[：:]\s*$"),
)
_SIGNATURE_BREAK_PATTERNS = (
    re.compile(r"^\s*(best regards|regards|thanks|thank you|谢谢|此致)\b", re.IGNORECASE),
    re.compile(r"^\s*--\s*$"),
)
_DISCLAIMER_BREAK_PATTERNS = (
    re.compile(r"^\s*this email and any attachments", re.IGNORECASE),
    re.compile(r"^\s*本邮件及其附件", re.IGNORECASE),
)

_APPROVE_PATTERNS = {
    "同意": re.compile(r"(?<!不)同意"),
    "通过": re.compile(r"(?<!不)通过"),
    "同意发布": re.compile(r"同意发布"),
    "批准": re.compile(r"批准"),
    "approve": re.compile(r"\bapprove(?:d)?\b", re.IGNORECASE),
}
_HOLD_PATTERNS = {
    "待定": re.compile(r"待定"),
    "待评估": re.compile(r"待评估"),
    "需补充材料": re.compile(r"需补充材料"),
    "需要评估": re.compile(r"需要评估"),
    "还需评估": re.compile(r"还需评估"),
    "需评估": re.compile(r"需评估"),
    "hold": re.compile(r"\bhold\b", re.IGNORECASE),
    "pending": re.compile(r"\bpending\b", re.IGNORECASE),
}
_REJECT_PATTERNS = {
    "驳回": re.compile(r"驳回"),
    "不同意": re.compile(r"不同意"),
    "不通过": re.compile(r"不通过"),
    "拒绝": re.compile(r"拒绝"),
    "reject": re.compile(r"\breject(?:ed)?\b", re.IGNORECASE),
}


@dataclass(frozen=True)
class ParsedDecision:
    decision: str
    normalized_text: str
    ambiguous: bool
    matched_terms: dict[str, tuple[str, ...]]


def normalize_reply_text(text: str) -> str:
    if not text:
        return ""
    kept: list[str] = []
    for raw_line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        stripped = raw_line.strip()
        if stripped.startswith(">"):
            continue
        if _matches_any(stripped, _REPLY_BREAK_PATTERNS):
            break
        if kept and _matches_any(stripped, _SIGNATURE_BREAK_PATTERNS):
            break
        if kept and _matches_any(stripped, _DISCLAIMER_BREAK_PATTERNS):
            break
        if stripped:
            kept.append(stripped)
    return "\n".join(kept).strip()


def classify_decision(text: str) -> ParsedDecision:
    normalized = normalize_reply_text(text)
    reject_terms = _find_terms(normalized, _REJECT_PATTERNS)
    approve_terms = _find_terms(normalized, _APPROVE_PATTERNS)
    hold_terms = _find_terms(normalized, _HOLD_PATTERNS)
    matched_terms = {
        "approve": tuple(approve_terms),
        "hold": tuple(hold_terms),
        "reject": tuple(reject_terms),
    }
    if reject_terms:
        return ParsedDecision("REJECT", normalized, False, matched_terms)
    if hold_terms:
        return ParsedDecision("HOLD", normalized, bool(approve_terms), matched_terms)
    if approve_terms:
        return ParsedDecision("APPROVE", normalized, False, matched_terms)
    return ParsedDecision("HOLD", normalized, True, matched_terms)


def _matches_any(value: str, patterns: tuple[re.Pattern[str], ...]) -> bool:
    return any(pattern.search(value) for pattern in patterns)


def _find_terms(value: str, patterns: dict[str, re.Pattern[str]]) -> list[str]:
    found: list[str] = []
    for label, pattern in patterns.items():
        if pattern.search(value):
            found.append(label)
    return found
