import boto3
from botocore.exceptions import ClientError
import pytest
from moto import mock_aws

from sentinel.checks.iam_mfa import check_users_without_mfa

PASSWORD = "Str0ng!Passw0rd#1"


@pytest.fixture
def iam():
    with mock_aws():
        yield boto3.client("iam", region_name="us-east-1")


def add_console_user(iam, name):
    iam.create_user(UserName=name)
    iam.create_login_profile(UserName=name, Password=PASSWORD, PasswordResetRequired=False)


def test_console_user_without_mfa_is_flagged(iam):
    add_console_user(iam, "alice")

    findings = check_users_without_mfa(iam)

    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-002"
    assert findings[0].severity == "HIGH"
    assert findings[0].resource == "iam:user/alice"


def test_user_with_only_access_keys_is_not_flagged(iam):
    iam.create_user(UserName="ci-bot")
    iam.create_access_key(UserName="ci-bot")

    assert check_users_without_mfa(iam) == []


def test_console_user_with_mfa_is_not_flagged(iam):
    add_console_user(iam, "bob")
    serial = iam.create_virtual_mfa_device(VirtualMFADeviceName="bob-device")[
        "VirtualMFADevice"
    ]["SerialNumber"]
    iam.enable_mfa_device(
        UserName="bob",
        SerialNumber=serial,
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )

    assert check_users_without_mfa(iam) == []


def test_only_the_user_missing_mfa_is_flagged(iam):
    add_console_user(iam, "alice")
    add_console_user(iam, "bob")
    serial = iam.create_virtual_mfa_device(VirtualMFADeviceName="bob-device")[
        "VirtualMFADevice"
    ]["SerialNumber"]
    iam.enable_mfa_device(
        UserName="bob",
        SerialNumber=serial,
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )

    findings = check_users_without_mfa(iam)

    assert [f.resource for f in findings] == ["iam:user/alice"]


def test_account_with_no_users_has_no_findings(iam):
    assert check_users_without_mfa(iam) == []

def test_check_is_skipped_when_get_login_profile_is_denied(iam, monkeypatch):
    add_console_user(iam, "alice")

    def denied(**kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "explicit deny in a service control policy"}},
            "GetLoginProfile",
        )

    monkeypatch.setattr(iam, "get_login_profile", denied)

    assert check_users_without_mfa(iam) == []
