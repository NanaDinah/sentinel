from datetime import datetime, timezone

from sentinel.findings import Finding

MAX_KEY_AGE_DAYS = 90


def check_old_access_keys(iam, now=None, max_age_days=MAX_KEY_AGE_DAYS):
    """Flag active IAM access keys older than max_age_days (IAM-001).

    `now` can be passed in so tests can simulate time passing.
    """
    now = now or datetime.now(timezone.utc)
    findings = []

    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                if key["Status"] != "Active":
                    continue
                age_days = (now - key["CreateDate"]).days
                if age_days > max_age_days:
                    key_id = key["AccessKeyId"]
                    findings.append(
                        Finding(
                            rule_id="IAM-001",
                            severity="MEDIUM",
                            resource=f"iam:user/{name}/access-key/{key_id}",
                            description=(
                                f"Access key {key_id} is {age_days} days old "
                                f"(limit {max_age_days})."
                            ),
                            remediation="Create a new key, switch your applications to it, then delete the old key.",
                        )
                    )
    return findings