import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "rd-flywheel" / "SKILL.md"


class HardInvariantTests(unittest.TestCase):
    def test_visual_click_is_versioned_design_evidence_only(self):
        text = SKILL.read_text(encoding="utf-8")
        for token in ("state/events", "HTML SHA-256", "VISUAL_DECISION_PENDING", "design consent only"):
            self.assertIn(token, text)

    def test_missing_required_capability_cannot_be_waived(self):
        text = SKILL.read_text(encoding="utf-8")
        for token in ("UNSUPPORTED -> CAPABILITY_BLOCKED", "originating checkpoint", "must not be waived"):
            self.assertIn(token, text)

    def test_original_event_checkpoint_is_preserved_and_replayed(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertIn("preserve the originating checkpoint", text)
        self.assertIn("replay the original immutable input", text)
        self.assertIn("preserving and resuming the original event", text)

    def test_ai_and_tools_return_evidence_not_authority(self):
        text = SKILL.read_text(encoding="utf-8")
        for token in (
            "evidence, never authority",
            "cannot grant credentials",
            "protected-branch merge",
            "independent review",
            "rollback",
        ):
            self.assertIn(token, text)

    def test_unattended_runtime_is_fail_closed_and_skip_missed(self):
        text = SKILL.read_text(encoding="utf-8")
        for token in (
            "kernel lock",
            "RUN_ALREADY_ACTIVE",
            "skip all missed intervals",
            "no approved agent adapter",
            "CAPABILITY_BLOCKED",
        ):
            self.assertIn(token, text)


if __name__ == "__main__":
    unittest.main()
