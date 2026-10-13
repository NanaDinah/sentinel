from botocore.exceptions import ClientError

from sentinel.findings import Finding

PUBLIC_GROUP_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}
BLOCK_SETTINGS = [
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
]


def _block_config(s3, bucket):
    try:
        return s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return None
        raise


def _policy_is_public(s3, bucket):
    try:
        return s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return False
        raise


def _acl_is_public(s3, bucket):
    grants = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    return any(g["Grantee"].get("URI") in PUBLIC_GROUP_URIS for g in grants)


def check_s3_public_buckets(s3):
    findings = []
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        arn = f"arn:aws:s3:::{name}"

        config = _block_config(s3, name)
        if config is None or not all(config.get(k) for k in BLOCK_SETTINGS):
            findings.append(
                Finding(
                    rule_id="S3-001",
                    severity="MEDIUM",
                    resource=arn,
                    description="Block Public Access is not fully enabled on this bucket.",
                    remediation="Enable all four Block Public Access settings.",
                )
            )

        if _policy_is_public(s3, name):
            findings.append(
                Finding(
                    rule_id="S3-002",
                    severity="CRITICAL",
                    resource=arn,
                    description="The bucket policy allows public access.",
                    remediation="Remove public principals from the bucket policy.",
                )
            )

        if _acl_is_public(s3, name):
            findings.append(
                Finding(
                    rule_id="S3-003",
                    severity="CRITICAL",
                    resource=arn,
                    description="The bucket ACL grants access to everyone.",
                    remediation="Remove public grants from the ACL and enable ACL blocking.",
                )
            )
    return findings
