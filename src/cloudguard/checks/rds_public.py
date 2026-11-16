from __future__ import annotations
from ..model import Finding
from ._util import account_id

class RdsPublic:
    id = "rds-public"; severity = "high"
    def run(self, session) -> list[Finding]:
        rds = session.client("rds"); acct = account_id(session)
        region = session.region_name or "us-east-1"; out = []
        for db in rds.describe_db_instances().get("DBInstances", []):
            if db.get("PubliclyAccessible", False):
                out.append(Finding(self.id, self.severity, db["DBInstanceArn"], acct, region,
                                   {"engine": db.get("Engine")}))
        return out
