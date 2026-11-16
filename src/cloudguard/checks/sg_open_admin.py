from __future__ import annotations
from ..model import Finding
from ._util import account_id

ADMIN_PORTS = [22, 3389, 3306, 5432]
def _covers(p, from_p, to_p):
    return from_p is not None and to_p is not None and from_p <= p <= to_p

class SgOpenAdmin:
    id = "sg-open-admin"; severity = "high"
    def run(self, session) -> list[Finding]:
        ec2 = session.client("ec2"); acct = account_id(session)
        region = session.region_name or "us-east-1"; out = []
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            hit = set()
            for perm in sg.get("IpPermissions", []):
                open_world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                if not open_world: continue
                fp, tp = perm.get("FromPort"), perm.get("ToPort")
                if perm.get("IpProtocol") == "-1":
                    hit.update(ADMIN_PORTS)
                else:
                    for p in ADMIN_PORTS:
                        if _covers(p, fp, tp): hit.add(p)
            if hit:
                out.append(Finding(self.id, self.severity, sg["GroupId"], acct, region,
                                   {"open_ports": sorted(hit), "cidr": "0.0.0.0/0"}))
        return out
