from pathlib import Path

from models import Finding, ScanResult
from rules import RULES


class DeVAICScanner:

    def __init__(self, rules=None):

        self.rules = rules if rules is not None else RULES

        self.compiled_rules = []

        for rule in self.rules:

            try:
                regex = rule.compile()

                self.compiled_rules.append(
                    (rule, regex)
                )

            except Exception as exc:

                print(
                    f"[ERROR] Invalid rule "
                    f"{rule.rule_id}: {exc}"
                )

    def scan_text(
        self,
        code: str,
        filename: str = "<string>"
    ) -> ScanResult:

        result = ScanResult(
            file=filename
        )

        lines = code.splitlines()

        for line_number, line in enumerate(
            lines,
            start=1
        ):

            for rule, regex in self.compiled_rules:

                try:

                    match = regex.search(line)

                except Exception as exc:

                    print(
                        f"[ERROR] Rule "
                        f"{rule.rule_id}: {exc}"
                    )

                    continue

                if match:

                    finding = Finding(
                        rule_id=rule.rule_id,
                        cwe=rule.cwe,
                        vulnerability=rule.vulnerability,
                        owasp=rule.owasp,
                        severity=rule.severity,
                        line=line_number,
                        code=line.strip(),
                        description=rule.description,
                        recommendation=rule.recommendation
                    )

                    result.findings.append(
                        finding
                    )

        return self._remove_duplicates(
            result
        )

    def scan_file(
        self,
        filename: str
    ) -> ScanResult:

        path = Path(filename)

        if not path.exists():

            raise FileNotFoundError(
                f"File not found: {filename}"
            )

        if not path.is_file():

            raise ValueError(
                f"Not a file: {filename}"
            )

        code = path.read_text(
            encoding="utf-8",
            errors="ignore"
        )

        return self.scan_text(
            code,
            str(path)
        )

    def scan_directory(
        self,
        directory: str
    ):

        path = Path(directory)

        if not path.exists():

            raise FileNotFoundError(
                f"Directory not found: {directory}"
            )

        if not path.is_dir():

            raise ValueError(
                f"Not a directory: {directory}"
            )

        results = []

        for file in path.rglob("*.py"):

            try:

                results.append(
                    self.scan_file(
                        str(file)
                    )
                )

            except Exception as exc:

                print(
                    f"[ERROR] Could not scan "
                    f"{file}: {exc}"
                )

        return results

    def _remove_duplicates(
        self,
        result: ScanResult
    ) -> ScanResult:

        unique = {}

        for finding in result.findings:

            key = (
                finding.rule_id,
                finding.line,
                finding.code
            )

            unique[key] = finding

        result.findings = list(
            unique.values()
        )

        return result