import boto3
import pytest
from moto import mock_aws

from sentinel.findings import Finding
from sentinel.store import save_findings


@pytest.fixture
def table():
    with mock_aws():
        db = boto3.resource("dynamodb", region_name="us-east-1")
        yield db.create_table(
            TableName="findings",
            KeySchema=[{"AttributeName": "finding_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "finding_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )


def make_finding(resource="arn:aws:s3:::demo"):
    return Finding(
        rule_id="S3-001",
        severity="MEDIUM",
        resource=resource,
        description="test",
        remediation="fix it",
    )


def get(table, finding):
    return table.get_item(Key={"finding_id": f"{finding.rule_id}#{finding.resource}"})["Item"]


def test_new_finding_is_saved_as_open(table):
    f = make_finding()
    result = save_findings(table, [f], now="2026-10-14T10:00:00")
    assert result == {"open": 1, "resolved": 0}
    item = get(table, f)
    assert item["status"] == "OPEN"
    assert item["first_seen"] == "2026-10-14T10:00:00"


def test_repeat_scan_keeps_first_seen_and_updates_last_seen(table):
    f = make_finding()
    save_findings(table, [f], now="2026-10-14T10:00:00")
    save_findings(table, [f], now="2026-10-15T10:00:00")
    item = get(table, f)
    assert item["first_seen"] == "2026-10-14T10:00:00"
    assert item["last_seen"] == "2026-10-15T10:00:00"


def test_fixed_finding_is_marked_resolved(table):
    f = make_finding()
    save_findings(table, [f], now="2026-10-14T10:00:00")
    result = save_findings(table, [], now="2026-10-15T10:00:00")
    assert result == {"open": 0, "resolved": 1}
    item = get(table, f)
    assert item["status"] == "RESOLVED"
    assert item["resolved_at"] == "2026-10-15T10:00:00"


def test_reappearing_finding_reopens(table):
    f = make_finding()
    save_findings(table, [f], now="2026-10-14T10:00:00")
    save_findings(table, [], now="2026-10-15T10:00:00")
    save_findings(table, [f], now="2026-10-16T10:00:00")
    item = get(table, f)
    assert item["status"] == "OPEN"
    assert "resolved_at" not in item
