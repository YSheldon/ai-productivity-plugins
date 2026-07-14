#!/usr/bin/env python3
"""Audit recipient visibility and transport metadata without printing addresses."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path


ORIGIN_IP_HEADERS = {"x-originating-ip", "x-client-ip"}
EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOSTNAME_RE = re.compile(r"\b(?:from|by)\s+[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.IGNORECASE)


def _addresses(message, name: str) -> list[str]:
    values = message.get_all(name, [])
    return [address for _, address in getaddresses(values) if address]


def audit(path: Path, mode: str, max_visible: int) -> dict:
    raw = path.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw)

    to_addresses = _addresses(message, "to")
    cc_addresses = _addresses(message, "cc")
    bcc_headers = len(message.get_all("bcc", []))
    origin_headers = sorted(
        name.lower()
        for name, _ in message.items()
        if name.lower() in ORIGIN_IP_HEADERS
    )
    received_values = message.get_all("received", [])
    received_count = len(received_values)
    received_hostname_count = sum(bool(HOSTNAME_RE.search(value)) for value in received_values)
    received_public_ipv4_count = 0
    for value in received_values:
        for candidate in IPV4_RE.findall(value):
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if address.version == 4 and address.is_global:
                received_public_ipv4_count += 1

    visible_count = len(to_addresses) + len(cc_addresses)
    malformed_visible = any(
        not EMAIL_RE.fullmatch(address)
        for address in to_addresses + cc_addresses
    )

    reasons: list[str] = []
    if not to_addresses:
        reasons.append("missing_visible_to")
    if cc_addresses:
        reasons.append("visible_cc")
    if bcc_headers:
        reasons.append("raw_bcc_header")
    if origin_headers:
        reasons.append("explicit_origin_ip_header")
    if malformed_visible:
        reasons.append("malformed_visible_recipient")
    if mode == "individual" and visible_count > max_visible:
        reasons.append("multiple_visible_recipients")

    if reasons:
        verdict = "block" if mode == "individual" or any(
            reason != "multiple_visible_recipients" for reason in reasons
        ) else "disclosure"
    elif visible_count > 1:
        verdict = "disclosure"
        reasons.append("multiple_visible_recipients")
    else:
        verdict = "pass"

    return {
        "verdict": verdict,
        "file": str(path),
        "mode": mode,
        "visible_to_count": len(to_addresses),
        "visible_cc_count": len(cc_addresses),
        "visible_recipient_count": visible_count,
        "raw_bcc_header_count": bcc_headers,
        "received_header_count": received_count,
        "received_hostname_count": received_hostname_count,
        "received_public_ipv4_count": received_public_ipv4_count,
        "explicit_origin_ip_header_count": len(origin_headers),
        "reasons": sorted(set(reasons)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("eml", type=Path)
    parser.add_argument("--mode", choices=("individual", "aggregate"), default="individual")
    parser.add_argument("--max-visible-recipient-addresses", type=int, default=1)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    if args.max_visible_recipient_addresses < 1:
        parser.error("--max-visible-recipient-addresses must be positive")
    try:
        result = audit(args.eml, args.mode, args.max_visible_recipient_addresses)
    except (OSError, ValueError):
        result = {"verdict": "block", "error": "unable_to_parse_message"}
        print(json.dumps(result, ensure_ascii=False), file=sys.stderr)
        return 2

    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if result["verdict"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
