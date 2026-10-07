from dataclasses import dataclass, field
from typing import List


@dataclass
class Finding:
    rule_id: str
    cwe: str
    vulnerability: str
    owasp: str
    severity: str
    line: int
    code: str
    description: str
    recommendation: str

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "vulnerability": self.vulnerability,
            "owasp": self.owasp,
            "severity": self.severity,
            "line": self.line,
            "code": self.code,
            "description": self.description,
            "recommendation": self.recommendation
        }


@dataclass
class ScanResult:
    file: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def vulnerable(self):
        return len(self.findings) > 0

    def to_dict(self):
        return {
            "file": self.file,
            "vulnerable": self.vulnerable,
            "total_findings": len(self.findings),
            "findings": [
                finding.to_dict()
                for finding in self.findings
            ]
        }