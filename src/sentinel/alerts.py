ALERT_SEVERITIES = {"HIGH", "CRITICAL"}


def send_alert(sns, topic_arn, findings):
    """Email about serious findings via SNS. Returns how many were included."""
    serious = [f for f in findings if f.severity in ALERT_SEVERITIES]
    if not serious:
        return 0

    lines = ["Sentinel found new high-severity issues:", ""]
    for f in serious:
        lines.append(f"[{f.severity}] {f.rule_id}  {f.resource}")
        lines.append(f"  Problem: {f.description}")
        lines.append(f"  Fix:     {f.remediation}")
        lines.append("")

    sns.publish(
        TopicArn=topic_arn,
        Subject=f"[Sentinel] {len(serious)} new high-severity finding(s)",
        Message="\n".join(lines),
    )
    return len(serious)
