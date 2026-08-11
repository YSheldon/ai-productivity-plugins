from __future__ import annotations

import sys
from pathlib import Path


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE_DIRECTORY))

from gitlab_mr_scope_gate import main, verify_release_gate  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
