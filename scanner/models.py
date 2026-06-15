from dataclasses import dataclass


@dataclass
class Finding:
    module: str
    severity: str
    url: str
    parameter: str
    evidence: str
    description: str
