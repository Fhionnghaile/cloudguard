# CloudGuard — serverless AWS misconfiguration scanner — manual

*One page, eight blocks. Every figure here comes from this repository's own tests and README.*

## 1. Claim
Six read-only checks (public S3, admin ports open to the world, wildcard IAM, unencrypted EBS, public RDS, CloudTrail off) are each proven to fire on a seeded misconfiguration, and stay quiet on clean resources, with no AWS account needed.

## 2. What it is
An event-driven scanner that finds risky AWS settings soon after they appear and records them in DynamoDB. Fixed findings are closed automatically instead of re-alerting.

## 3. Demo
Architecture diagram: `docs/architecture.mmd`. Capture to record: the moto-backed test run.

## 4. Run it yourself
**Prerequisites:** Python 3. Terraform and a sandbox AWS account only if deploying.

```bash
pip install -e ".[dev]"
PYTHONPATH=src pytest -q
```

## 5. What you will see
6 tests pass against mocked AWS (moto).

## 6. 30-second talking point
> The gap between "someone opened a bucket" and "we knew" is where breaches live. CloudGuard closes it with a read-only scanner, a DynamoDB design built around the actual queries, and reconciliation, so fixed issues close rather than nag.

## 7. Scope and limits
- Six checks as a reference set. A production deployment grows the catalogue.
- AWS-specific. The pattern ports; the checks do not.
- Deploy only into a sandbox account seeded with deliberate misconfigurations.

## 8. Links
[Repository](https://github.com/fhionnghaile/cloudguard) · [Write-up](https://padraigfhionnghaile.com/work/cloudguard/) · [README](README.md)
