from __future__ import annotations
from typing import Protocol, runtime_checkable
from .model import Finding

@runtime_checkable
class Check(Protocol):
    id: str
    severity: str
    def run(self, session) -> list[Finding]:
        """Read-only. Return current violations, or raise (never a partial list)."""
        ...
