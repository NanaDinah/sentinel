from botocore.exceptions import ClientError

from sentinel.findings import Finding


def _has_console_password(iam, user_name):
    """True if the user can sign in to the console (has a login profile)."""
    try:
        iam.get_login_profile(UserName=user_name)
        return True
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise


def check_users_without_mfa(iam):
    """Flag IAM users who can sign in to the console but have no MFA device (IAM-002).

    Users with only access keys are skipped: MFA protects the console password.
    """
    findings = []

    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            if not _has_console_password(iam, name):
                continue
            if iam.list_mfa_devices(UserName=name)["MFADevices"]:
                continue
            findings.append(
                Finding(
                    rule_id="IAM-002",
                    severity="HIGH",
                    resource=f"iam:user/{name}",
                    description="This user can sign in to the console but has no MFA device.",
                    remediation="Register an authenticator app or security key for the user, or remove their console password.",
                )
            )
    return findings