from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Callable


def resolve_lark_cli_command(
    *,
    platform_name: str | None = None,
    search_path: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> tuple[str, ...]:
    effective_platform = platform_name or os.name
    if effective_platform != "nt":
        return (which("lark-cli") or "lark-cli",)

    native_executable = which("lark-cli.exe")
    if native_executable:
        return (native_executable,)

    node_executable = which("node.exe") or which("node")
    effective_path = os.environ.get("PATH", "") if search_path is None else search_path
    if node_executable:
        for raw_directory in effective_path.split(os.pathsep):
            directory = raw_directory.strip().strip('"')
            if not directory:
                continue
            node_entry = (
                Path(directory)
                / "node_modules"
                / "@larksuite"
                / "cli"
                / "scripts"
                / "run.js"
            )
            try:
                if node_entry.is_file():
                    return (node_executable, str(node_entry.resolve()))
            except OSError:
                continue

    return ("lark-cli",)
