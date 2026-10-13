from datetime import datetime, timezone

from boto3.dynamodb.conditions import Attr

NAMES = {
    "#rule": "rule_id",
    "#sev": "severity",
    "#res": "resource",
    "#desc": "description",
    "#rem": "remediation",
    "#st": "status",
    "#first": "first_seen",
    "#last": "last_seen",
    "#resolved": "resolved_at",
}


def finding_id(finding):
    return f"{finding.rule_id}#{finding.resource}"


def _open_items(table):
    kwargs = {"FilterExpression": Attr("status").eq("OPEN")}
    while True:
        page = table.scan(**kwargs)
        yield from page["Items"]
        if "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def save_findings(table, findings, now=None):
    """Upsert current findings as OPEN and mark vanished ones RESOLVED."""
    now = now or datetime.now(timezone.utc).isoformat()
    current = set()

    for f in findings:
        fid = finding_id(f)
        current.add(fid)
        table.update_item(
            Key={"finding_id": fid},
            UpdateExpression=(
                "SET #rule=:rule, #sev=:sev, #res=:res, #desc=:desc, #rem=:rem, "
                "#st=:open, #last=:now, #first=if_not_exists(#first, :now) "
                "REMOVE #resolved"
            ),
            ExpressionAttributeNames=NAMES,
            ExpressionAttributeValues={
                ":rule": f.rule_id,
                ":sev": f.severity,
                ":res": f.resource,
                ":desc": f.description,
                ":rem": f.remediation,
                ":open": "OPEN",
                ":now": now,
            },
        )

    resolved = 0
    for item in list(_open_items(table)):
        if item["finding_id"] not in current:
            table.update_item(
                Key={"finding_id": item["finding_id"]},
                UpdateExpression="SET #st=:resolved, #resolved=:now",
                ExpressionAttributeNames={"#st": "status", "#resolved": "resolved_at"},
                ExpressionAttributeValues={":resolved": "RESOLVED", ":now": now},
            )
            resolved += 1

    return {"open": len(current), "resolved": resolved}
