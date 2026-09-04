"""Loads the teaching prose that makes this a companion rather than a scanner.

All user-facing explanation lives in ``teaching_content/`` as Markdown, keyed by
each module's ``teaching_key`` (PRD 9.2, 10). Module code never contains prose,
so the explanations can be edited without touching Python.

File format - one file per key::

    # Human readable title

    ## before
    What this does and why it matters, before it runs.

    ## after
    How to read the result.

    ## next
    - Suggested next step
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

CONTENT_DIR = Path(__file__).resolve().parent.parent / "teaching_content"
_SECTION_RE = re.compile(r"^##\s+(before|after|next)\s*$", re.I | re.M)


@dataclass(slots=True)
class Lesson:
    key: str
    title: str
    before: str = ""
    after: str = ""
    next_steps: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.before or self.after or self.next_steps)


def _parse(key: str, text: str) -> Lesson:
    title = key.replace("_", " ").title()
    body = text
    first = text.lstrip()
    if first.startswith("# "):
        line, _, rest = first.partition("\n")
        title = line[2:].strip()
        body = rest

    sections: dict[str, str] = {}
    matches = list(_SECTION_RE.finditer(body))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        sections[match.group(1).lower()] = body[match.end() : end].strip()

    steps = [
        line.lstrip("-* ").strip()
        for line in sections.get("next", "").splitlines()
        if line.strip().startswith(("-", "*"))
    ]
    return Lesson(
        key=key,
        title=title,
        before=sections.get("before", "").strip(),
        after=sections.get("after", "").strip(),
        next_steps=steps,
    )


class TeachingLibrary:
    """Reads lessons and the glossary from disk, with a small cache."""

    def __init__(self, content_dir: Path | str | None = None) -> None:
        self.content_dir = Path(content_dir) if content_dir else CONTENT_DIR
        self._cache: dict[str, Lesson] = {}
        self._glossary: dict[str, str] | None = None

    def lesson(self, key: str) -> Lesson:
        if not key:
            return Lesson(key="", title="")
        if key in self._cache:
            return self._cache[key]
        path = self.content_dir / f"{key}.md"
        if path.exists():
            lesson = _parse(key, path.read_text(encoding="utf-8"))
        else:
            lesson = Lesson(key=key, title=key.replace("_", " ").title())
        self._cache[key] = lesson
        return lesson

    def glossary(self) -> dict[str, str]:
        if self._glossary is None:
            path = self.content_dir / "glossary.md"
            entries: dict[str, str] = {}
            if path.exists():
                current: str | None = None
                buffer: list[str] = []
                for line in path.read_text(encoding="utf-8").splitlines():
                    if line.startswith("## "):
                        if current:
                            entries[current] = "\n".join(buffer).strip()
                        current = line[3:].strip().lower()
                        buffer = []
                    elif current:
                        buffer.append(line)
                if current:
                    entries[current] = "\n".join(buffer).strip()
            self._glossary = entries
        return self._glossary

    def define(self, term: str) -> tuple[str, str] | None:
        """Exact match first, then a forgiving substring match."""
        needle = (term or "").strip().lower()
        if not needle:
            return None
        glossary = self.glossary()
        if needle in glossary:
            return needle, glossary[needle]
        for name, body in glossary.items():
            if needle in name or name in needle:
                return name, body
        return None

    def terms(self) -> list[str]:
        return sorted(self.glossary())


@lru_cache(maxsize=1)
def default_library() -> TeachingLibrary:
    return TeachingLibrary()
