from __future__ import annotations

import json
import sys
from pathlib import Path


def _load_bootstrap_module(repo_root: Path):
    module_path = repo_root / "plugins" / "product-release-gate" / "scripts" / "bootstrap_dependencies.py"
    namespace: dict[str, object] = {}
    exec(module_path.read_text(encoding="utf-8"), namespace)
    return namespace


def bootstrap_profile(profile: str, *, repo_root: str | Path) -> dict[str, object]:
    root = Path(repo_root).resolve()
    module = _load_bootstrap_module(root)
    profiles = dict(module["PROFILES"])
    profiles["test-submission"] = (
        "imap-smtp-mail",
        "product-release-gate",
        "lark-cli",
    )
    module["PROFILES"] = profiles
    return dict(module["bootstrap_profile"](profile, repo_root=root))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print("usage: bootstrap_dependencies.py <profile> <repo_root>", file=sys.stderr)
        return 2
    payload = bootstrap_profile(args[0], repo_root=args[1])
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
