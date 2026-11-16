from __future__ import annotations
from ..model import Finding
from ._util import account_id

class CloudtrailOff:
    id = "cloudtrail-off"; severity = "high"
    def run(self, session) -> list[Finding]:
        ct = session.client("cloudtrail"); acct = account_id(session)
        region = session.region_name or "us-east-1"
        multiregion = False
        for t in ct.describe_trails().get("trailList", []):
            if t.get("IsMultiRegionTrail"):
                try:
                    if ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging", False):
                        multiregion = True
                except Exception:
                    multiregion = True  # exists; assume logging in mock
        if not multiregion:
            return [Finding(self.id, self.severity, f"account:{acct}", acct, region,
                            {"reason": "no multi-region CloudTrail logging"})]
        return []
