"""Optional external tools, executed safely (PRD 9.4, 9.5).

Nothing here is required: every capability has a pure-Python path. When a tool
*is* present we use it for extra depth, and we execute it with the hardening the
PRD mandates - no shell, list arguments, an ``--`` end-of-options separator,
a timeout, and an output size cap.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Sequence

from .errors import TargetValidationError
from .scope import validate_target

MAX_OUTPUT_BYTES = 512 * 1024


@dataclass(slots=True)
class ToolResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int
    truncated: bool = False


def which(name: str) -> str | None:
    """Absolute path of *name* if it is on PATH, else ``None``."""
    return shutil.which(name)


def detect_version(name: str, flag: str = "--version", timeout: int = 5) -> str | None:
    """Best-effort version string for an optional tool, for run provenance."""
    path = which(name)
    if not path:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - fixed args, no shell
            [path, flag],
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (completed.stdout or completed.stderr or "").strip().splitlines()
    return output[0][:120] if output else None


def run_tool(
    name: str,
    fixed_args: Sequence[str],
    targets: Sequence[str],
    *,
    timeout: int = 30,
    use_separator: bool = True,
) -> ToolResult:
    """Run an optional tool with strictly validated, list-form arguments.

    ``targets`` are user-derived and are validated with
    :func:`~recon_helper_pro.core.scope.validate_target` before they can reach
    the process, then placed after ``--`` so a crafted value cannot be read as
    a flag. Nothing is ever interpolated into a command line.
    """
    path = which(name)
    if not path:
        return ToolResult(False, "", f"{name} is not installed.", 127)

    safe_targets = []
    for target in targets:
        try:
            safe_targets.append(validate_target(target))
        except TargetValidationError as exc:
            return ToolResult(False, "", str(exc), 2)

    args = [path, *fixed_args]
    if use_separator and safe_targets:
        args.append("--")
    args.extend(safe_targets)

    try:
        completed = subprocess.run(  # noqa: S603 - fixed args, no shell
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(False, "", f"{name} timed out after {timeout}s.", 124)
    except OSError as exc:
        return ToolResult(False, "", f"{name} could not be started: {exc}", 126)

    stdout = completed.stdout or ""
    truncated = len(stdout.encode("utf-8", "ignore")) > MAX_OUTPUT_BYTES
    if truncated:
        stdout = stdout.encode("utf-8", "ignore")[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
    return ToolResult(
        ok=completed.returncode == 0 and bool(stdout.strip()),
        stdout=stdout,
        stderr=(completed.stderr or "")[:4000],
        returncode=completed.returncode,
        truncated=truncated,
    )
