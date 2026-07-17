import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "rd-flywheel" / "SKILL.md"


class SkillContractTests(unittest.TestCase):
    def test_skill_has_no_scaffold_placeholders(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertNotIn("TODO", text)
        self.assertNotIn("[TODO", text)

    def test_skill_encodes_flywheel_invariants(self):
        text = SKILL.read_text(encoding="utf-8")
        required = {
            "authoritative repository",
            "actual request",
            "bootstrap trust root",
            "Visual Companion",
            "CAPABILITY_BLOCKED",
            "UNSUPPORTED",
            "production canary",
            "OBSERVED",
            "HARVESTED",
            "CLOSED",
        }
        missing = sorted(token for token in required if token not in text)
        self.assertFalse(missing, f"missing flywheel invariants: {missing}")

    def test_references_are_linked_and_present(self):
        text = SKILL.read_text(encoding="utf-8")
        references = {
            "visual-decision-gates.md",
            "first-practice.md",
            "evidence-and-completion.md",
            "tool-routing.md",
            "pressure-scenarios.md",
        }
        for name in references:
            self.assertIn(f"references/{name}", text)
            self.assertTrue((SKILL.parent / "references" / name).is_file())

    def test_description_is_trigger_only(self):
        lines = SKILL.read_text(encoding="utf-8").splitlines()
        description = next(line for line in lines if line.startswith("description:"))
        self.assertTrue(description.startswith("description: Use when "))
        self.assertLessEqual(len(description), 1024)

    def test_visual_gate_has_authority_boundary(self):
        text = (SKILL.parent / "references" / "visual-decision-gates.md").read_text(encoding="utf-8")
        self.assertIn("No event means `VISUAL_DECISION_PENDING`", text)
        self.assertIn("must never replace Feishu approval", text)
        self.assertIn("screen_sha256", text)

    def test_skill_routes_through_same_four_surface_runtime(self):
        text = SKILL.read_text(encoding="utf-8")
        for token in (
            "MCP first",
            "CLI fallback",
            "rd_flywheel_cli.py",
            "run-once",
            "verify-audit",
            "scheduler install",
            "same controller",
            "Codex is optional",
        ):
            self.assertIn(token, text)

    def test_plugin_manifest_and_mcp_entrypoint_are_declared(self):
        manifest = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        mcp = json.loads((ROOT / ".mcp.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["name"], "rd-flywheel")
        self.assertIn("mcpServers", mcp)
        args = mcp["mcpServers"]["rd-flywheel"]["args"]
        self.assertIn("./src/rd_flywheel_mcp.py", args)


if __name__ == "__main__":
    unittest.main()
