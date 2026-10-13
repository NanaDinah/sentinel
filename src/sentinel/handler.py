import json
import logging

import boto3

from sentinel.checks.s3_public import check_s3_public_buckets
from sentinel.checks.security_groups import check_open_security_groups

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def run_scan(s3=None, ec2=None):
    s3 = s3 or boto3.client("s3")
    ec2 = ec2 or boto3.client("ec2")
    findings = []
    findings.extend(check_s3_public_buckets(s3))
    findings.extend(check_open_security_groups(ec2))
    return findings


def lambda_handler(event, context):
    logger.info("Sentinel scan started")
    findings = [f.to_dict() for f in run_scan()]
    logger.info("Sentinel scan finished: %d findings", len(findings))
    return {"statusCode": 200, "body": json.dumps({"findings": findings})}
