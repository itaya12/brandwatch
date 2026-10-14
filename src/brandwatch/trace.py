"""Per-scan trace log: the full detail of what the scanner did and how, for tuning and debugging.

The live console (scan_events) tells the analyst *what* happens; the trace tells the engineer
*exactly how*: every provider call with its input and output (the LLM prompt and raw answer
included), every generated look-alike name and its DNS answer, each candidate's DNS / HTTP /
forms / hashes / WHOIS, every signal with its points and reason, and the scoring arithmetic.

One text file per job under ``<evidence_dir>/_traces/scan-<job_id>.log`` — readable as is —
served by ``GET /api/jobs/{id}/trace``. Secrets are redacted with the same filter as the console.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_current: ContextVar[ScanTrace | None] = ContextVar("brandwatch_trace", default=None)

MAX_VALUE = 1200  # characters kept per logged value (the LLM prompt/answer get more)
MAX_LLM = 12000


def _short(value: Any, limit: int = MAX_VALUE) -> Any:
    """Compact, JSON-safe, bounded rendering of a logged value."""
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + f"… (+{len(value) - limit} chars)"
    if isinstance(value, dict):
        return {str(k): _short(v, limit) for k, v in list(value.items())[:60]}
    if isinstance(value, list | tuple | set):
        items = list(value)
        out = [_short(v, limit) for v in items[:3000]]
        if len(items) > 3000:
            out.append(f"… (+{len(items) - 3000} more)")
        return out
    if hasattr(value, "value") and not callable(value.value):  # enums
        return value.value
    return _short(str(value), limit)


class ScanTrace:
    def __init__(self, job_id: uuid.UUID, path: Path, *, secrets: list[str] | None = None) -> None:
        self.job_id = job_id
        self.path = path
        self._secrets = sorted(
            {s for s in (secrets or []) if s and len(s) >= 6}, key=len, reverse=True
        )
        self._lock = threading.Lock()
        self._t0 = time.monotonic()
        self.lines = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._write(
            f"# BrandWatch scan trace · job {job_id} · started {datetime.now(UTC).isoformat()}\n"
        )

    # -- writing --------------------------------------------------------------------------------
    def _redact(self, text: str) -> str:
        for s in self._secrets:
            text = text.replace(s, "***")
        return text

    def _write(self, text: str) -> None:
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(self._redact(text))
            self.lines += 1

    def log(self, stage: str, message: str, **data: Any) -> None:
        """One line: elapsed · stage · message · compact JSON of the details."""
        stamp = f"{time.monotonic() - self._t0:9.3f}s"
        extra = ""
        if data:
            limit = MAX_LLM if stage.startswith("llm") else MAX_VALUE
            extra = " " + json.dumps(_short(data, limit), ensure_ascii=False, default=str)
        self._write(f"[{stamp}] [{stage}] {message}{extra}\n")

    def section(self, title: str) -> None:
        self._write(f"\n==== {title} ====\n")

    # -- context --------------------------------------------------------------------------------
    def __enter__(self) -> ScanTrace:
        self._token = _current.set(self)
        return self

    def __exit__(self, *exc: Any) -> None:
        _current.reset(self._token)
        self.log("trace", "end of trace", lines=self.lines)


def start(
    job_id: uuid.UUID, evidence_dir: str | Path, secrets: list[str] | None = None
) -> ScanTrace:
    """Open the trace for the current task (the scan worker's coroutine) and make it current."""
    t = ScanTrace(job_id, trace_path(evidence_dir, job_id), secrets=secrets)
    _current.set(t)
    return t


def current() -> ScanTrace | None:
    return _current.get()


def log(stage: str, message: str, **data: Any) -> None:
    """Log to the current scan's trace, if any (no-op outside a scan)."""
    t = _current.get()
    if t is not None:
        t.log(stage, message, **data)


def section(title: str) -> None:
    t = _current.get()
    if t is not None:
        t.section(title)


def trace_path(evidence_dir: str | Path, job_id: uuid.UUID) -> Path:
    return Path(evidence_dir) / "_traces" / f"scan-{job_id}.log"
