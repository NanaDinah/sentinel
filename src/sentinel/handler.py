import json
import logging

import boto3

from sentinel.checks.s3_public import check_s3_public_buckets

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def run_scan(s3=None):
    s3 = s3 or boto3.client("s3")
    findings = []
    findings.extend(check_s3_public_buckets(s3))
    return findings


def lambda_handler(event, context):
    logger.info("Sentinel scan started")
    findings = [f.to_dict() for f in run_scan()]
    logger.info("Sentinel scan finished: %d findings", len(findings))
    return {"statusCode": 200, "body": json.dumps({"findings": findings})}
