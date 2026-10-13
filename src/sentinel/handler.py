import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info("Sentinel scan started")
    findings = []
    logger.info("Sentinel scan finished: %d findings", len(findings))
    return {"statusCode": 200, "body": json.dumps({"findings": findings})}
