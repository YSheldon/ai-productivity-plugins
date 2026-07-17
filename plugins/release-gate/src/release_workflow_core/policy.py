from __future__ import annotations

from typing import Any, Sequence

from .validation import ValidationError, canonical_json, freeze_digest


_LOCAL_MANDATORY_BY_MODULE: dict[str, tuple[str, ...]] = {
    "kernel": (
        "artifacts_present",
        "hashes_match",
        "version_present",
        "signature_present",
        "cloud_scan_required",
    ),
    "client": (
        "artifacts_present",
        "hashes_match",
        "version_present",
        "signature_present",
        "cloud_scan_required",
    ),
    "server": (
        "artifacts_present",
        "hashes_match",
        "source_revision_present",
        "package_digest_present",
        "cloud_scan_required",
    ),
}
_SVN_MANDATORY = (
    "provenance_locator_present",
    "fixed_revision_present",
    "trusted_retrieval_succeeded",
    "retrieved_nonempty",
    "audit_recorded",
)
_VERDICT_GATED_CHECKS = frozenset(("cloud_scan_required", "shared_kernel_release_gate"))

CANONICAL_MANDATORY_MINIMUMS: dict[str, Any] = {
    "local": dict(_LOCAL_MANDATORY_BY_MODULE),
    "svn": _SVN_MANDATORY,
}


def canonical_mandatory_minimums(module: str, *, retrieval_method: str = "local") -> tuple[str, ...]:
    method = str(retrieval_method or "local").strip().lower()
    key = str(module or "").strip().lower()
    if method == "svn":
        return _SVN_MANDATORY
    if key not in _LOCAL_MANDATORY_BY_MODULE:
        raise ValidationError(f"unsupported workflow module: {module}.")
    return _LOCAL_MANDATORY_BY_MODULE[key]


def missing_canonical_mandatory(
    module: str,
    configured_mandatory: Sequence[str],
    *,
    retrieval_method: str = "local",
) -> tuple[str, ...]:
    configured = tuple(str(item).strip() for item in configured_mandatory if str(item).strip())
    return tuple(
        item
        for item in canonical_mandatory_minimums(module, retrieval_method=retrieval_method)
        if item not in configured
    )


def effective_checks(
    module: str,
    *,
    configured_mandatory: Sequence[str],
    enabled_optional: Sequence[str] = (),
    retrieval_method: str = "local",
) -> tuple[str, ...]:
    method = str(retrieval_method or "local").strip().lower()
    missing = missing_canonical_mandatory(
        module,
        configured_mandatory,
        retrieval_method=method,
    )
    if missing:
        raise ValidationError(
            f"configured mandatory checks drifted for {method}:{module}: {', '.join(missing)}."
        )
    ordered: list[str] = []
    for value in (
        *canonical_mandatory_minimums(module, retrieval_method=method),
        *(str(item).strip() for item in configured_mandatory),
        *(str(item).strip() for item in enabled_optional),
    ):
        if value and value not in ordered:
            ordered.append(value)
    if not ordered:
        raise ValidationError("effective checks cannot be empty.")
    return tuple(ordered)


def required_verdict(effective_check_list: Sequence[str]) -> str:
    checks = {str(item).strip() for item in effective_check_list if str(item).strip()}
    return "CLEAN" if checks.intersection(_VERDICT_GATED_CHECKS) else ""


def freeze_policy(
    module: str,
    *,
    policy_profile: str,
    configured_mandatory: Sequence[str],
    enabled_optional: Sequence[str] = (),
    retrieval_method: str = "local",
) -> dict[str, Any]:
    profile = str(policy_profile or "").strip()
    if not profile:
        raise ValidationError("policy_profile must be a non-empty string.")
    method = str(retrieval_method or "local").strip().lower()
    record = {
        "schema": "ProductMaterialPolicy/v1",
        "module": str(module or "").strip().lower(),
        "retrieval_method": method,
        "policy_profile": profile,
        "canonical_mandatory_minimums": list(
            canonical_mandatory_minimums(module, retrieval_method=method)
        ),
        "configured_mandatory": list(
            dict.fromkeys(str(item).strip() for item in configured_mandatory if str(item).strip())
        ),
        "enabled_optional": list(
            dict.fromkeys(str(item).strip() for item in enabled_optional if str(item).strip())
        ),
    }
    record["effective_checks"] = list(
        effective_checks(
            record["module"],
            retrieval_method=method,
            configured_mandatory=record["configured_mandatory"],
            enabled_optional=record["enabled_optional"],
        )
    )
    record["required_verdict"] = required_verdict(record["effective_checks"])
    record["policy_digest"] = freeze_digest(record)
    record["frozen_json"] = canonical_json({key: value for key, value in record.items() if key != "frozen_json"})
    return record
