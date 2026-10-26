# Sentinel

[![CI](https://github.com/NanaDinah/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/NanaDinah/sentinel/actions/workflows/ci.yml)

Sentinel is a small, serverless security auditor for an AWS account. On a schedule it scans for common misconfigurations, stores the results, and emails you when a new serious problem appears. When a problem is fixed, Sentinel notices and marks it resolved.

## How it works

```
EventBridge (daily) -> Lambda (Python 3.12, read-only scan) -> DynamoDB (findings)
                                                            -> SNS (email alerts)
```

- The Lambda role only has read permissions for the services it audits, plus write access to its own table and topic.
- Each finding is saved with a status of open or resolved. A finding that disappears from a later scan is marked resolved.
- An email is sent only for **new HIGH and CRITICAL** findings. MEDIUM findings are saved but do not send email, and a finding is not re-alerted on every scan.
- Everything is defined in Terraform.

## What it checks

| Rule | Severity | What it flags |
|---|---|---|
| S3-001 | MEDIUM | Block Public Access is not fully enabled on a bucket |
| S3-002 | CRITICAL | A bucket policy allows public access |
| S3-003 | CRITICAL | A bucket ACL grants access to everyone |
| SG-001 | HIGH | SSH (22) or RDP (3389) open to the internet |
| SG-002 | HIGH | A database port (MySQL, PostgreSQL, SQL Server, MongoDB, Redis) open to the internet |
| SG-003 | CRITICAL | All inbound traffic open to the internet |
| IAM-001 | MEDIUM | An active access key older than 90 days |
| IAM-002 | HIGH | A user with a console password but no MFA device |

Sentinel flags the author's honeypot security group (SG-001, SSH open) on purpose. That one open finding is expected.

## Deploy

You need Terraform 1.10 or later, AWS credentials, and an S3 bucket for Terraform state. Edit the `backend "s3"` block in `terraform/main.tf` to point at your own bucket.

```bash
cd terraform
terraform init
terraform apply -var alert_email=you@example.com
```

Confirm the subscription email that SNS sends to you, or alerts will not arrive. The scan runs once a day by default (`scan_schedule` in `variables.tf`). To run one now:

```bash
aws lambda invoke --function-name sentinel-auditor --region eu-north-1 /tmp/out.json
jq -r '.body' /tmp/out.json | jq '.summary'
```

## Demo

`demo/` creates deliberately insecure but harmless resources so you can watch findings appear, trigger an alert email, and then clear after cleanup. See [demo/README.md](demo/README.md).

## Tests and CI

```bash
pip install -r requirements-dev.txt
PYTHONPATH=src pytest
```

GitHub Actions runs three jobs on every push and pull request:

- **tests**: the unit tests, which use mocked AWS services.
- **terraform**: `fmt`, `init` and `validate` for both `terraform/` and `demo/`.
- **iac-scan**: a Checkov scan of `terraform/`. It is informational and does not fail the build.

## Known limitations

- Some AWS Organizations policies deny `iam:GetLoginProfile`. In that case IAM-002 is skipped with a warning instead of failing the whole scan. A unit test covers this case.
- Scanning covers the region Sentinel is deployed in.

## Roadmap

- [x] S3 public access checks (S3-001 to S3-003)
- [x] Security group checks (SG-001 to SG-003)
- [x] IAM checks (IAM-001, IAM-002)
- [x] Findings stored in DynamoDB with open and resolved status
- [x] Email alerts for new HIGH and CRITICAL findings
- [x] Scheduled scans with EventBridge
- [x] Unit tests and CI with Terraform validation and a Checkov scan
- [x] Demo that shows findings appearing and clearing

## Next steps

- Check EBS volume encryption
- Check that CloudTrail is enabled
- Scan multiple regions
- Deploy through a CI pipeline using GitHub OIDC instead of manual `terraform apply`
