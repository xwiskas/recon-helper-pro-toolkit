"""A deliberately tiny Markdown renderer for the teaching panels.

Teaching prose ships with the app, so it is trusted - but it is still escaped
first and only a fixed set of inline forms is re-introduced afterwards. That way
this function stays safe even if someone later points it at text that came from
a target.

Report previews do **not** go through here: they are shown as escaped
preformatted text, because a report contains hostnames, headers and page titles
the target controls.
"""

from __future__ import annotations

import html
import re

from markupsafe import Markup

_BOLD = re.compile(r"\*\*(.+?)\*\*", re.S)
_CODE = re.compile(r"`([^`]+)`")


def _inline(text: str) -> str:
    escaped = html.escape(text, quote=False)
    escaped = _CODE.sub(lambda match: f"<code>{match.group(1)}</code>", escaped)
    escaped = _BOLD.sub(lambda match: f"<strong>{match.group(1)}</strong>", escaped)
    return escaped


def teaching_html(text: str) -> Markup:
    """Render trusted teaching Markdown: paragraphs, bullet lists, bold, code."""
    if not text:
        return Markup("")

    blocks: list[str] = []
    paragraph: list[str] = []
    bullets: list[str] = []

    def flush() -> None:
        if paragraph:
            blocks.append("<p>" + _inline(" ".join(paragraph)) + "</p>")
            paragraph.clear()
        if bullets:
            items = "".join(f"<li>{_inline(item)}</li>" for item in bullets)
            blocks.append(f"<ul>{items}</ul>")
            bullets.clear()

    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            flush()
            continue
        if stripped.startswith(("- ", "* ")):
            if paragraph:
                blocks.append("<p>" + _inline(" ".join(paragraph)) + "</p>")
                paragraph.clear()
            bullets.append(stripped[2:].strip())
            continue
        if bullets and line.startswith(("  ", "\t")):
            bullets[-1] += " " + stripped  # continuation of the previous bullet
            continue
        if bullets:
            flush()
        paragraph.append(stripped)

    flush()
    return Markup("".join(blocks))


def shorten(text: str, limit: int = 120) -> str:
    """Trim a value for a table cell without hiding that it was trimmed."""
    value = " ".join(str(text or "").split())
    return value if len(value) <= limit else value[: limit - 1] + "…"
