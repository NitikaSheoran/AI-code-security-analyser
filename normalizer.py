import re


class CodeNormalizer:
    """
    Normalizes Python source code for pattern comparison.

    This module is useful when building vulnerability rules from
    a dataset of vulnerable code.

    The scanner itself preserves the original source so that
    reported line numbers remain accurate.
    """

    INPUT_NAMES = {
        "user_input",
        "request_data",
        "input_data",
        "payload",
        "user_data",
        "request_data",
        "value"
    }

    def normalize(self, code: str) -> str:
        code = self._remove_comments(code)
        code = self._normalize_whitespace(code)
        code = self._normalize_identifiers(code)

        return code

    def _remove_comments(self, code: str) -> str:

        result = []

        for line in code.splitlines():

            stripped = line.strip()

            # Remove full-line comments.
            if stripped.startswith("#"):
                continue

            # Don't aggressively remove '#' from strings.
            # This handles the most common source-code cases.
            line = re.sub(
                r"\s+#.*$",
                "",
                line
            )

            result.append(line)

        return "\n".join(result)

    def _normalize_whitespace(self, code: str) -> str:

        lines = []

        for line in code.splitlines():

            line = line.strip()

            if not line:
                continue

            line = re.sub(
                r"\s+",
                " ",
                line
            )

            lines.append(line)

        return "\n".join(lines)

    def _normalize_identifiers(self, code: str) -> str:

        for name in self.INPUT_NAMES:

            code = re.sub(
                rf"\b{re.escape(name)}\b",
                "INPUT",
                code
            )

        return code


if __name__ == "__main__":

    code = """
    # Example vulnerable code

    user_input = request.args.get("cmd")

    result = eval(user_input)
    """

    normalizer = CodeNormalizer()

    print("Original:")
    print(code)

    print("\nNormalized:")
    print(normalizer.normalize(code))