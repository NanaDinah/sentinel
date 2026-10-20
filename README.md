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
   Expect new HIGH and CRITICAL findings (SG-001, SG-002, S3-001, S3-002) and an alert email.
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
- Run `terraform destroy` as soon as the demo is done.