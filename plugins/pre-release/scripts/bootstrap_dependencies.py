from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


_PRODUCT_GATE_SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "product-release-gate"
    / "scripts"
    / "bootstrap_dependencies.py"
)
if str(_PRODUCT_GATE_SCRIPT.parent) not in sys.path:
    sys.path.insert(0, str(_PRODUCT_GATE_SCRIPT.parent))

from bootstrap_dependencies import bootstrap_profile as _bootstrap_profile  # type: ignore  # noqa: E402


def bootstrap_profile(
    profile: str = "product-release-gate",
    *,
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    del profile
    return _bootstrap_profile("product-release-gate", repo_root=repo_root)
