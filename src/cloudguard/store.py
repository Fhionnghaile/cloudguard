from __future__ import annotations
import time
from .model import Finding

RESOLVED_TTL_DAYS = 30

class FindingStore:
    """DynamoDB single-table store. Reconciles a check's current findings with stored state."""
    def __init__(self, table):
        self.t = table

    @staticmethod
    def _keys(f: Finding, status: str, first_seen: int):
        return {
            "PK": f"ACCT#{f.account_id}",
            "SK": f"FINDING#{f.check_id}#{f.resource}",
            "GSI1PK": f"ACCT#{f.account_id}#{status}",
            "GSI1SK": f"SEV#{f.rank()}#{first_seen}",
            "GSI2PK": f"RES#{f.resource}",
            "GSI2SK": f"FINDING#{f.check_id}",
        }

    def reconcile(self, account_id: str, check_id: str, current: list[Finding], now: int | None = None) -> dict:
        now = int(time.time()) if now is None else now
        from boto3.dynamodb.conditions import Key
        existing = self.t.query(
            KeyConditionExpression=Key("PK").eq(f"ACCT#{account_id}") & Key("SK").begins_with(f"FINDING#{check_id}#")
        ).get("Items", [])
        by_sk = {i["SK"]: i for i in existing}
        cur_sks = {f"FINDING#{f.check_id}#{f.resource}": f for f in current}
        opened = updated = resolved = 0

        for sk, f in cur_sks.items():
            prev = by_sk.get(sk)
            first_seen = int(prev["first_seen"]) if prev and "first_seen" in prev else now
            item = {**self._keys(f, "open", first_seen),
                    "severity": f.severity, "status": "open", "first_seen": first_seen,
                    "last_seen": now, "detail": f.detail, "region": f.region}
            self.t.put_item(Item=item)
            if prev and prev.get("status") == "open": updated += 1
            else: opened += 1

        for sk, prev in by_sk.items():
            if sk in cur_sks or prev.get("status") != "open": continue
            prev["status"] = "resolved"; prev["last_seen"] = now
            prev["GSI1PK"] = prev["GSI1PK"].rsplit("#", 1)[0] + "#resolved"
            prev["ttl"] = now + RESOLVED_TTL_DAYS * 86400   # auto-expire resolved
            self.t.put_item(Item=prev); resolved += 1

        return {"opened": opened, "updated": updated, "resolved": resolved}
