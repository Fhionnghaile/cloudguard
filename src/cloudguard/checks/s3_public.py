from __future__ import annotations
import json
from ..model import Finding
from ._util import account_id

class S3Public:
    id = "s3-public"; severity = "critical"
    def run(self, session) -> list[Finding]:
        s3 = session.client("s3"); acct = account_id(session); out = []
        for b in s3.list_buckets().get("Buckets", []):
            name = b["Name"]; reasons = []
            try:
                cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            except Exception:
                cfg = {}
            if not all(cfg.get(k, False) for k in
                       ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                # BPA not fully on — check for actual public ACL / policy
                try:
                    for g in s3.get_bucket_acl(Bucket=name).get("Grants", []):
                        uri = g.get("Grantee", {}).get("URI", "")
                        if uri.endswith("AllUsers") or uri.endswith("AuthenticatedUsers"):
                            reasons.append("acl:public-grant")
                except Exception:
                    pass
                try:
                    pol = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
                    for st in pol.get("Statement", []):
                        pr = st.get("Principal")
                        if st.get("Effect") == "Allow" and (pr == "*" or pr == {"AWS": "*"}):
                            reasons.append("policy:principal-star")
                except Exception:
                    pass
            if reasons:
                out.append(Finding(self.id, self.severity, f"arn:aws:s3:::{name}", acct, "global",
                                   {"reasons": sorted(set(reasons))}))
        return out
