import boto3
import pytest
from moto import mock_aws

from sentinel.alerts import send_alert
from sentinel.findings import Finding


@pytest.fixture
def sns():
    with mock_aws():
        yield boto3.client("sns", region_name="us-east-1")


def make_finding(severity):
    return Finding(
        rule_id="SG-001",
        severity=severity,
        resource="ec2:security-group/sg-123",
        description="SSH is open to the internet.",
        remediation="Limit access to your own IP.",
    )


def test_serious_findings_trigger_an_alert(sns):
    topic = sns.create_topic(Name="alerts")["TopicArn"]
    sent = send_alert(sns, topic, [make_finding("CRITICAL"), make_finding("HIGH")])
    assert sent == 2


def test_low_severity_findings_do_not_alert(sns):
    topic = sns.create_topic(Name="alerts")["TopicArn"]
    assert send_alert(sns, topic, [make_finding("MEDIUM"), make_finding("LOW")]) == 0


def test_no_findings_means_no_alert(sns):
    topic = sns.create_topic(Name="alerts")["TopicArn"]
    assert send_alert(sns, topic, []) == 0
