import boto3
import pytest
from moto import mock_aws

from sentinel.checks.security_groups import check_open_security_groups


@pytest.fixture
def ec2():
    with mock_aws():
        yield boto3.client("ec2", region_name="us-east-1")


def make_group(ec2, permissions):
    group_id = ec2.create_security_group(GroupName="test-sg", Description="test")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=permissions)
    return group_id


def rules_for(findings, group_id):
    return {f.rule_id for f in findings if group_id in f.resource}


def tcp(port, cidr="0.0.0.0/0"):
    return {
        "IpProtocol": "tcp",
        "FromPort": port,
        "ToPort": port,
        "IpRanges": [{"CidrIp": cidr}],
    }


def test_ssh_open_to_world_is_flagged(ec2):
    gid = make_group(ec2, [tcp(22)])
    assert "SG-001" in rules_for(check_open_security_groups(ec2), gid)


def test_ssh_restricted_to_private_range_is_clean(ec2):
    gid = make_group(ec2, [tcp(22, "10.0.0.0/8")])
    assert rules_for(check_open_security_groups(ec2), gid) == set()


def test_ipv6_open_ssh_is_flagged(ec2):
    gid = make_group(
        ec2,
        [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}],
    )
    assert "SG-001" in rules_for(check_open_security_groups(ec2), gid)


def test_database_port_open_to_world_is_flagged(ec2):
    gid = make_group(ec2, [tcp(3306)])
    assert "SG-002" in rules_for(check_open_security_groups(ec2), gid)


def test_all_traffic_open_is_critical(ec2):
    gid = make_group(ec2, [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    findings = [f for f in check_open_security_groups(ec2) if gid in f.resource]
    assert any(f.rule_id == "SG-003" and f.severity == "CRITICAL" for f in findings)
