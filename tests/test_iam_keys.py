from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws

from sentinel.checks.iam_keys import check_old_access_keys


@pytest.fixture
def iam():
    with mock_aws():
        yield boto3.client("iam", region_name="us-east-1")


def days_from_now(days):
    return datetime.now(timezone.utc) + timedelta(days=days)


def test_flags_key_older_than_the_limit(iam):
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")

    findings = check_old_access_keys(iam, now=days_from_now(100))

    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-001"
    assert findings[0].severity == "MEDIUM"
    assert "alice" in findings[0].resource


def test_recent_key_is_not_flagged(iam):
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")

    assert check_old_access_keys(iam) == []


def test_key_exactly_at_the_limit_is_not_flagged(iam):
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")

    assert check_old_access_keys(iam, now=days_from_now(90)) == []


def test_inactive_key_is_not_flagged(iam):
    iam.create_user(UserName="alice")
    key_id = iam.create_access_key(UserName="alice")["AccessKey"]["AccessKeyId"]
    iam.update_access_key(UserName="alice", AccessKeyId=key_id, Status="Inactive")

    assert check_old_access_keys(iam, now=days_from_now(200)) == []


def test_user_without_keys_is_not_flagged(iam):
    iam.create_user(UserName="bob")

    assert check_old_access_keys(iam, now=days_from_now(200)) == []


def test_each_old_key_gets_its_own_finding(iam):
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")
    iam.create_access_key(UserName="alice")

    findings = check_old_access_keys(iam, now=days_from_now(100))

    assert len(findings) == 2
    assert len({f.resource for f in findings}) == 2