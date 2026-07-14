#!/usr/bin/env python3
"""Fail-closed wire-format audit for a serialized daily bulletin email."""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from pathlib import Path


def decoded_header(value: str | None) -> str:
    if not value:
        return ""
    return str(make_header(decode_header(value))).strip()


def header_value(raw_headers: bytes, name: str) -> str:
    match = re.search(
        rb"(?im)^" + re.escape(name.encode("ascii")) + rb":([^\r\n]*(?:\r?\n[ \t][^\r\n]*)*)",
        raw_headers,
    )
    if not match:
        return ""
    return match.group(1).decode("utf-8", errors="replace").strip()


def part_text(message, content_type: str) -> str:
    for part in message.walk():
        if part.is_multipart() or part.get_content_type() != content_type:
            continue
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    return ""


def visible_html_chars(value: str) -> int:
    without_noise = re.sub(r"(?is)<(?:script|style)\b.*?</(?:script|style)>", " ", value)
    text = re.sub(r"(?s)<[^>]+>", " ", without_noise)
    return len(re.sub(r"\s+", " ", html.unescape(text)).strip())


def audit(raw: bytes, expected_subject: str, strict_layout: bool, min_body_chars: int) -> dict[str, object]:
    raw_headers = raw.split(b"\r\n\r\n", 1)[0]
    message = BytesParser(policy=policy.compat32).parsebytes(raw)
    raw_subject = header_value(raw_headers, "Subject")
    decoded_subject = decoded_header(raw_subject)
    plain = part_text(message, "text/plain")
    html_body = part_text(message, "text/html")
    problems: list[str] = []
    if not raw_subject:
        problems.append("raw Subject header is missing")
    if decoded_subject != expected_subject:
        problems.append("decoded Subject does not exactly match expected subject")
    if message.get_content_type().lower() != "multipart/alternative":
        problems.append("message is not multipart/alternative")
    if len(plain.strip()) < min_body_chars:
        problems.append("plain-text body is empty or too short")
    if len(html_body.strip()) < min_body_chars:
        problems.append("HTML body is empty or too short")
    if visible_html_chars(html_body) < min_body_chars:
        problems.append("HTML has insufficient visible text")
    if strict_layout:
        if not re.search(r'<table[^>]+role=["\']presentation["\'][^>]+width=["\']100%["\']', html_body, re.I):
            problems.append("HTML lacks full-width outer presentation table")
        if not re.search(r'<table[^>]+role=["\']presentation["\'][^>]+width=["\']720["\']', html_body, re.I):
            problems.append("HTML lacks 720px inner presentation table")
        if "max-width:96%" not in html_body.replace(" ", "").lower():
            problems.append("HTML inner shell lacks responsive max-width")
    return {
        "expected_subject": expected_subject,
        "raw_subject": raw_subject,
        "decoded_subject": decoded_subject,
        "content_type": message.get_content_type(),
        "plain_chars": len(plain),
        "html_chars": len(html_body),
        "visible_html_chars": visible_html_chars(html_body),
        "strict_layout": strict_layout,
        "decision": "pass" if not problems else "block",
        "problems": problems,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("eml", type=Path)
    parser.add_argument("--expected-subject", required=True)
    parser.add_argument("--strict-layout", action="store_true")
    parser.add_argument("--min-body-chars", type=int, default=200)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    result = audit(args.eml.read_bytes(), args.expected_subject, args.strict_layout, args.min_body_chars)
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if result["decision"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
