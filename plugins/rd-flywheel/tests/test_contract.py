import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
CONTRACT = REPO / "contracts" / "rd-flywheel" / "capability-gap-event-v1.json"


def test_capability_gap_contract_is_versioned_and_requires_identity_bindings():
    schema = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert schema["$id"].endswith("/capability-gap-event-v1.json")
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "schema",
        "originating_plugin",
        "originating_event_id",
        "originating_round_id",
        "checkpoint_digest",
        "missing_capability",
        "required_evidence",
        "allowed_tool_profiles",
        "created_at",
        "idempotency_key",
    }
    assert schema["properties"]["schema"]["const"] == "CapabilityGapEvent/v1"
    assert schema["properties"]["checkpoint_digest"]["pattern"] == "^[a-f0-9]{64}$"


def test_contract_requires_each_production_evidence_category():
    schema = json.loads(CONTRACT.read_text(encoding="utf-8"))
    required = set(schema["properties"]["required_evidence"]["allOf"][0]["contains"]["enum"])
    assert {
        "tests",
        "independent_review",
        "protected_merge",
        "package_publication",
        "installation",
        "first_practice",
        "rollback",
        "checkpoint_replay",
    } <= required
