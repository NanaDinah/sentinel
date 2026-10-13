# sentinel
## Security design

- **Least privilege:** The Lambda's IAM role is read-only for the services it audits (S3, EC2, IAM, CloudTrail). Its only write permission is to its own DynamoDB findings table, not to `*`.
- **No stored credentials:** Nothing in this repo contains AWS keys, and a gitleaks pre-commit hook blocks accidental commits of secrets.
- **Remote state:** Terraform state lives in a private, versioned S3 bucket with encryption and locking, created manually first because Terraform can't store state in a bucket that doesn't exist yet.