"""Keep one serial classification worker per dashboard session."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from threading import Lock, Thread

from jev_ids.adversarial.classification import Classification

__all__ = ["Batch", "Progress"]


@dataclass(frozen=True, slots=True)
class Progress:
    """Atomic view for a Streamlit rerun."""

    rows: tuple[Classification, ...]
    total: int
    busy: bool
    error: str | None

    @property
    def can_continue(self) -> bool:
        """Return whether the batch can accept another step."""
        return not self.busy and not self.error and len(self.rows) < self.total


class Batch:
    """Advance one lazy iterator without calling Streamlit from a worker."""

    def __init__(self, source: Iterator[Classification], total: int, step_size: int = 1) -> None:
        """Create a paused batch without opening the dataset or the model."""
        self._source = source
        self._total = total
        self._step_size = step_size
        self._rows: list[Classification] = []
        self._lock = Lock()
        self._busy = False
        self._error: str | None = None

    def snapshot(self) -> Progress:
        """Read rows, error and worker status together."""
        with self._lock:
            return Progress(tuple(self._rows), self._total, self._busy, self._error)

    def advance(self, *, all_remaining: bool = False) -> None:
        """Start one step or the remaining batch exactly once."""
        with self._lock:
            remaining = self._total - len(self._rows)
            if self._busy or self._error or remaining <= 0:
                return
            self._busy = True
        Thread(target=self._consume, args=(remaining if all_remaining else min(remaining, self._step_size),), daemon=True).start()

    def _consume(self, count: int) -> None:
        try:
            for _ in range(count):
                row = next(self._source)
                with self._lock:
                    self._rows.append(row)
        except Exception as exc:
            with self._lock:
                self._error = f"{type(exc).__name__}: {exc}"
        finally:
            with self._lock:
                self._busy = False
