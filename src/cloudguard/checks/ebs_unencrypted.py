from __future__ import annotations
from ..model import Finding
from ._util import account_id

class EbsUnencrypted:
    id = "ebs-unencrypted"; severity = "medium"
    def run(self, session) -> list[Finding]:
        ec2 = session.client("ec2"); acct = account_id(session)
        region = session.region_name or "us-east-1"; out = []
        for v in ec2.describe_volumes().get("Volumes", []):
            if not v.get("Encrypted", False):
                out.append(Finding(self.id, self.severity, v["VolumeId"], acct, region,
                                   {"size_gb": v.get("Size")}))
        return out
