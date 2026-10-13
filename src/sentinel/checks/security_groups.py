from sentinel.findings import Finding

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DB_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "SQL Server",
    27017: "MongoDB",
    6379: "Redis",
}


def _open_to_world(rule):
    v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
    v6 = any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []))
    return v4 or v6


def _covered_ports(rule, ports):
    if rule.get("IpProtocol") != "tcp":
        return set()
    low = rule.get("FromPort", 0)
    high = rule.get("ToPort", 65535)
    return {p for p in ports if low <= p <= high}


def check_open_security_groups(ec2):
    findings = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            group_id = sg["GroupId"]
            resource = f"ec2:security-group/{group_id}"
            all_open = False
            admin = set()
            db = set()

            for rule in sg.get("IpPermissions", []):
                if not _open_to_world(rule):
                    continue
                if rule.get("IpProtocol") == "-1":
                    all_open = True
                    continue
                admin |= _covered_ports(rule, ADMIN_PORTS)
                db |= _covered_ports(rule, DB_PORTS)

            if all_open:
                findings.append(
                    Finding(
                        rule_id="SG-003",
                        severity="CRITICAL",
                        resource=resource,
                        description="All inbound traffic is open to the internet.",
                        remediation="Restrict the rule to specific ports and trusted IP ranges.",
                    )
                )
            if admin:
                names = ", ".join(ADMIN_PORTS[p] for p in sorted(admin))
                findings.append(
                    Finding(
                        rule_id="SG-001",
                        severity="HIGH",
                        resource=resource,
                        description=f"{names} is open to the internet.",
                        remediation="Limit access to your own IP or use a VPN or Session Manager.",
                    )
                )
            if db:
                names = ", ".join(DB_PORTS[p] for p in sorted(db))
                findings.append(
                    Finding(
                        rule_id="SG-002",
                        severity="HIGH",
                        resource=resource,
                        description=f"Database port(s) open to the internet: {names}.",
                        remediation="Place the database in a private subnet and allow only app servers.",
                    )
                )
    return findings
