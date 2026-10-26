# Sentinel demo: findings appear, alert, then clear

This folder creates deliberately insecure resources so Sentinel has something to find. They are harmless: the security group is attached to nothing and the bucket is empty. It uses its own local state and is applied by hand, never by CI.

## Run the demo

1. Create the insecure resources:
   ```bash
   cd demo
   terraform init
   terraform apply
   ```
2. Run a scan and watch the findings appear:
   ```bash
   aws lambda invoke --function-name sentinel-auditor --region eu-north-1 /tmp/out.json
   jq -r '.body' /tmp/out.json | jq '.summary'
   ```
   Expect four new findings next to the honeypot's: SG-001 (HIGH), SG-002 (HIGH), S3-002 (CRITICAL) and S3-001 (MEDIUM). The three HIGH and CRITICAL ones trigger an alert email. S3-001 is only MEDIUM, so it is saved without an email.
3. Fix the problems by removing the resources:
   ```bash
   terraform destroy
   ```
4. Scan again. The same findings now show as **resolved**:
   ```bash
   aws lambda invoke --function-name sentinel-auditor --region eu-north-1 /tmp/out.json
   jq -r '.body' /tmp/out.json | jq '.summary'
   ```

## Notes

- If `terraform apply` fails on the public bucket policy, the AWS account has account-level Block Public Access enabled. That is a good setting; leave it on, and demo only the security group findings.
- Run `terraform destroy` in the same session as `terraform apply`. The demo state is stored locally, so losing it means deleting the resources by hand.
