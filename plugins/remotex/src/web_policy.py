from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import remotex_core as core


def endpoint(value: Any) -> tuple[str, str]:
    url = core._required_text(value, "url")
    if re.search(r"[\\\s%]", url) or any(ord(c) < 32 for c in url):
        raise core.ToolError("Web URL must not contain whitespace, escapes or backslashes")
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query:
            raise ValueError()
        if parsed.fragment and not re.fullmatch(r"[A-Za-z0-9_./-]*", parsed.fragment):
            raise ValueError()
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        host = f"[{host}]" if ":" in host else host
        port = parsed.port
        if port == 0:
            raise ValueError()
    except (ValueError, UnicodeError) as exc:
        raise core.ToolError("Web login requires an absolute HTTPS URL without userinfo or query") from exc
    authority = host + (f":{port}" if port and port != 443 else "")
    origin = "https://" + authority
    return urlunsplit(("https", authority, parsed.path or "/", "", parsed.fragment)), origin


def account(value: Any) -> str:
    name = core._required_text(value, "account")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}", name):
        raise core.ToolError("Web account must be a non-secret account identifier")
    return name


def selector(value: Any, name: str, optional: bool = False) -> str | None:
    if optional and value in (None, ""):
        return None
    text = core._required_text(value, name)
    if not re.fullmatch(r"#[A-Za-z][A-Za-z0-9_-]{0,95}", text):
        raise core.ToolError(f"{name} must select one explicit element ID")
    return text


def binding_id(origin: str, user: str) -> str:
    return hashlib.sha256((origin + "\0" + user).encode("utf-8")).hexdigest()


def certificate_pin(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"(?:[A-Fa-f0-9]{64}|(?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2})", value):
        raise core.ToolError("certificate_sha256 must be one complete SHA-256 certificate fingerprint")
    return value.replace(":", "").lower()


def credential(origin: str, user: str) -> dict[str, str]:
    return {"source":"windows-credential-manager", "target":"RemoteX/Web/" + binding_id(origin, user),
            "web_origin":origin,"web_account":user}


def profile(args: dict[str, Any], alias: str) -> dict[str, Any]:
    url, origin = endpoint(args.get("url"))
    user = account(args.get("account"))
    selectors = {k: selector(args.get(k), k, k == "success_selector") for k in
                 ("username_selector", "password_selector", "submit_selector", "success_selector")}
    if len(set(v for v in selectors.values() if v)) != len([v for v in selectors.values() if v]):
        raise core.ToolError("Web login selectors must be distinct")
    resource = "web:" + binding_id(origin, user)
    if args.get("queue_resource") not in (None, resource):
        raise core.ToolError("Web queue resource must match the origin/account binding")
    result = {"kind":"web","url":url,"origin":origin,"account":user,"browser":"edge",
            "credential_ref":alias,"queue_resource":resource,"queue_lease_seconds":1800, **selectors}
    if "certificate_sha256" in args:
        result["certificate_sha256"] = certificate_pin(args["certificate_sha256"])
    return result


def validate_binding(raw: dict[str, Any], record: dict[str, Any]) -> None:
    expected = profile(raw, core._required_text(raw.get("credential_ref"), "credential_ref"))
    if set(raw) != set(expected) or any(raw.get(k) != expected[k] for k in expected):
        raise core.ToolError("Web profile binding is invalid; use web profile setup")
    if record != credential(expected["origin"], expected["account"]):
        raise core.ToolError("Web credential is not bound to this origin and account")
