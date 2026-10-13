import boto3
import pytest
from moto import mock_aws

from sentinel.checks.s3_public import check_s3_public_buckets

FULL_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


@pytest.fixture
def s3():
    with mock_aws():
        yield boto3.client("s3", region_name="us-east-1")


def rule_ids(findings):
    return {f.rule_id for f in findings}


def test_no_buckets_means_no_findings(s3):
    assert check_s3_public_buckets(s3) == []


def test_bucket_without_block_public_access_is_flagged(s3):
    s3.create_bucket(Bucket="no-block")
    assert "S3-001" in rule_ids(check_s3_public_buckets(s3))


def test_fully_blocked_bucket_is_clean(s3):
    s3.create_bucket(Bucket="locked")
    s3.put_public_access_block(
        Bucket="locked", PublicAccessBlockConfiguration=FULL_BLOCK
    )
    assert check_s3_public_buckets(s3) == []


def test_public_acl_is_flagged(s3):
    s3.create_bucket(Bucket="open", ACL="public-read")
    assert "S3-003" in rule_ids(check_s3_public_buckets(s3))
