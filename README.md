# CloudGuard — serverless AWS misconfiguration scanner

<!-- at-a-glance -->
> **Catches an insecure cloud resource the moment it appears.**  
> **Result:** 6 tests against moto (mocked AWS) — the whole scanner proven end-to-end with no account or bill.  
> **Reproduce:** `pytest -q`  
> ![CI](https://github.com/fhionnghaile/cloudguard/actions/workflows/ci.yml/badge.svg) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Fhionnghaile/cloudguard/badge)](https://scorecard.dev/viewer/?uri=github.com/Fhionnghaile/cloudguard)
>
> **What this is worth:** Shrinks the window between 'someone opened an S3 bucket' and 'we knew' from weeks to seconds.


Event-driven scanner: **EventBridge → Lambda → DynamoDB**, dashboarded, auto-remediating a *safe*
subset — **all Terraform, all least-privilege**. The scanner is **read-only** (AWS-managed
`SecurityAudit`); it only *writes* to its own findings table.

## Architecture
See [`docs/architecture.mmd`](docs/architecture.mmd).
```
EventBridge (1h) → Scanner Lambda → [read-only AWS APIs]
                        │ reconcile
                        ▼
                   DynamoDB (single table, GSI1 by severity, GSI2 by resource, TTL on resolved)
                        └→ Read API (API GW + Lambda) → Dashboard
```

## The checks
| id | severity | detects |
|---|---|---|
| `s3-public` | critical | bucket public via ACL or policy / BPA off |
| `sg-open-admin` | high | SG allows `0.0.0.0/0` to 22 / 3389 / 3306 / 5432 |
| `iam-wildcard` | high | customer policy with `Action:"*"` **and** `Resource:"*"` |
| `ebs-unencrypted` | medium | EBS volume not encrypted |
| `rds-public` | high | RDS instance publicly accessible |
| `cloudtrail-off` | high | no multi-region CloudTrail logging |

Each `Check.run(session)` is read-only, returns current violations, and **raises on failure** (never a
partial list) — a check that raises is skipped, not reconciled.

## DynamoDB single-table design
**Access patterns:** open findings per account · findings per resource · findings by severity · a
finding's history · auto-expire resolved.

| | value |
|---|---|
| PK / SK | `ACCT#<acct>` / `FINDING#<check>#<resource>` |
| GSI1 (by severity) | `ACCT#<acct>#<status>` / `SEV#<rank>#<first_seen>` |
| GSI2 (by resource) | `RES#<resource>` / `FINDING#<check>` |
| TTL | `ttl` set only when `status=resolved` (now + 30d) |

Reconcile preserves `first_seen`, refreshes `last_seen`, and resolves findings that are gone.

## Test it (no AWS account needed)
The whole scanner is tested against **moto** (mocked AWS):
```bash
pip install -e ".[dev]" && PYTHONPATH=src pytest -q   # 6 passed
```
Seeds real misconfigs in a mock account and asserts each check fires (and clean resources don't).

## Deploy it
```bash
cd terraform && terraform init && terraform apply
```
Least-privilege IAM: `SecurityAudit` (read) + write to **only** the findings table. Deploy into a
**sandbox account seeded with deliberate misconfigs** — never real data, especially for screenshots.

## License
MIT.

## Key decisions

- Event-driven (EventBridge→Lambda→DynamoDB), so detection is immediate, not a nightly scan.
- Single-table DynamoDB modelled around the access patterns, with a TTL for ageing findings.
- Reconciliation closes fixed findings instead of re-alerting — signal over noise.

## Scope & limits

- Six checks as a reference set; a production deployment grows the catalogue.
- AWS-specific — the pattern ports but the checks don't.

