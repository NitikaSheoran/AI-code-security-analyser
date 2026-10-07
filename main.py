import argparse
from pathlib import Path

from scanner import DeVAICScanner
from reporter import Reporter


def main():

    parser = argparse.ArgumentParser(
        description=(
            "DeVAIC-style security scanner "
            "for AI-generated Python code."
        )
    )

    parser.add_argument(
        "target",
        help=(
            "Python file or directory to scan."
        )
    )

    parser.add_argument(
        "--output",
        default="reports/report.json",
        help=(
            "JSON report path. "
            "Default: reports/report.json"
        )
    )

    args = parser.parse_args()

    scanner = DeVAICScanner()

    target = Path(args.target)

    if target.is_file():

        results = [
            scanner.scan_file(
                str(target)
            )
        ]

    elif target.is_dir():

        results = scanner.scan_directory(
            str(target)
        )

    else:

        print(
            f"ERROR: Target does not exist: "
            f"{target}"
        )

        return 1

    for result in results:

        Reporter.print_result(
            result
        )

    Reporter.summary(
        results
    )

    Reporter.save_json(
        results,
        args.output
    )

    print(
        f"\nReport saved to: "
        f"{args.output}"
    )

    return 0


if __name__ == "__main__":

    raise SystemExit(
        main()
    )