from __future__ import annotations
from dataclasses import dataclass, field

SEVERITY_RANK = {"critical": 1, "high": 2, "medium": 3, "low": 4}

@dataclass(frozen=True)
class Finding:
    check_id: str
    severity: str
    resource: str        # ARN or stable id
    account_id: str
    region: str
    detail: dict = field(default_factory=dict)

    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]
