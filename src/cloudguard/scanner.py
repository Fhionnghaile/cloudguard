from __future__ import annotations
import os, boto3
from .checks import ALL_CHECKS
from .store import FindingStore
from .checks._util import account_id

def handler(event=None, context=None):
    session = boto3.Session()
    table = boto3.resource("dynamodb").Table(os.environ.get("TABLE", "cloudguard"))
    store = FindingStore(table)
    acct = account_id(session)
    summary = {}
    for check in ALL_CHECKS:
        try:
            findings = check.run(session)       # a failing check is skipped, not reconciled
        except Exception as e:                  # noqa: BLE001
            summary[check.id] = {"error": str(e)}; continue
        summary[check.id] = store.reconcile(acct, check.id, findings)
    return {"account": acct, "checks": summary}
