from dataclasses import dataclass, asdict


@dataclass
class Finding:
    rule_id: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    resource: str
    description: str
    remediation: str

    def to_dict(self):
        return asdict(self)
