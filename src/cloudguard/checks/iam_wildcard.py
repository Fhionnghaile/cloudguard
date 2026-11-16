from __future__ import annotations
import json, urllib.parse
from ..model import Finding
from ._util import account_id

def _aslist(x): return x if isinstance(x, list) else [x]

class IamWildcard:
    id = "iam-wildcard"; severity = "high"
    def run(self, session) -> list[Finding]:
        iam = session.client("iam"); acct = account_id(session); out = []
        for pol in iam.list_policies(Scope="Local").get("Policies", []):
            ver = iam.get_policy_version(PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"])
            doc = ver["PolicyVersion"]["Document"]
            if isinstance(doc, str): doc = json.loads(urllib.parse.unquote(doc))
            for st in _aslist(doc.get("Statement", [])):
                if st.get("Effect") != "Allow": continue
                actions = _aslist(st.get("Action", []))
                resources = _aslist(st.get("Resource", []))
                act_star = any(a == "*" or a == "*:*" for a in actions)
                res_star = any(r == "*" for r in resources)
                if act_star and res_star:
                    out.append(Finding(self.id, self.severity, pol["Arn"], acct, "global",
                                       {"policy": pol["PolicyName"], "action": "*", "resource": "*"}))
                    break
        return out
