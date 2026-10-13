import json
import logging
import os

import boto3

from sentinel.alerts import send_alert
from sentinel.checks.s3_public import check_s3_public_buckets
from sentinel.checks.security_groups import check_open_security_groups
from sentinel.store import save_findings

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
    findings = run_scan()

    summary = {}
    table_name = os.environ.get("FINDINGS_TABLE")
    if table_name:
        table = boto3.resource("dynamodb").Table(table_name)
        new_findings = []
        summary = save_findings(table, findings, new_findings=new_findings)

        topic_arn = os.environ.get("ALERT_TOPIC_ARN")
        if topic_arn:
            summary["alerts_sent"] = send_alert(boto3.client("sns"), topic_arn, new_findings)

    logger.info("Sentinel scan finished: %d findings, %s", len(findings), summary)
    body = {"findings": [f.to_dict() for f in findings], "summary": summary}
    return {"statusCode": 200, "body": json.dumps(body)}
