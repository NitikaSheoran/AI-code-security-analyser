import json
from collections import Counter
from pathlib import Path


class Reporter:

    @staticmethod
    def print_result(result):

        print("\n" + "=" * 75)

        print(
            f"FILE: {result.file}"
        )

        print("=" * 75)

        if not result.findings:

            print("STATUS: SAFE")
            print(
                "No matching vulnerability patterns found."
            )

            return

        print(
            "STATUS: POTENTIALLY VULNERABLE"
        )

        print(
            f"FINDINGS: {len(result.findings)}"
        )

        print()

        for finding in result.findings:

            print("-" * 75)

            print(
                f"[{finding.severity}] "
                f"{finding.vulnerability}"
            )

            print(
                f"CWE          : {finding.cwe}"
            )

            print(
                f"OWASP        : {finding.owasp}"
            )

            print(
                f"Rule         : {finding.rule_id}"
            )

            print(
                f"Line         : {finding.line}"
            )

            print(
                f"Code         : {finding.code}"
            )

            print(
                f"Description  : {finding.description}"
            )

            print(
                f"Recommendation: "
                f"{finding.recommendation}"
            )

    @staticmethod
    def summary(results):

        total_files = len(results)

        vulnerable_files = sum(
            1
            for result in results
            if result.vulnerable
        )

        total_findings = sum(
            len(result.findings)
            for result in results
        )

        severity_counter = Counter()

        owasp_counter = Counter()

        cwe_counter = Counter()

        for result in results:

            for finding in result.findings:

                severity_counter[
                    finding.severity
                ] += 1

                owasp_counter[
                    finding.owasp
                ] += 1

                cwe_counter[
                    finding.cwe
                ] += 1

        print("\n" + "=" * 75)
        print("SCAN SUMMARY")
        print("=" * 75)

        print(
            f"Files scanned       : {total_files}"
        )

        print(
            f"Vulnerable files    : {vulnerable_files}"
        )

        print(
            f"Total findings      : {total_findings}"
        )

        print("\nSeverity:")

        if severity_counter:

            for severity, count in (
                severity_counter.most_common()
            ):

                print(
                    f"  {severity:10} : {count}"
                )

        else:

            print("  None")

        print("\nOWASP categories:")

        if owasp_counter:

            for category, count in (
                owasp_counter.most_common()
            ):

                print(
                    f"  {category} : {count}"
                )

        else:

            print("  None")

        print("\nCWEs:")

        if cwe_counter:

            for cwe, count in (
                cwe_counter.most_common()
            ):

                print(
                    f"  {cwe:10} : {count}"
                )

        else:

            print("  None")

    @staticmethod
    def save_json(
        results,
        filename
    ):

        path = Path(filename)

        # Automatically create reports/
        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        data = [
            result.to_dict()
            for result in results
        ]

        with open(
            path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                data,
                file,
                indent=4
            )