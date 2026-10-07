# from scanner import DeVAICScanner


# class AISecurityLoop:

#     def __init__(self, scanner):

#         self.scanner = scanner

#     def analyze(self, generated_code):

#         result = self.scanner.scan_text(
#             generated_code
#         )

#         return result

#     def create_remediation_prompt(self, code, result):

#         if not result.findings:

#             return None

#         findings = []

#         for finding in result.findings:

#             findings.append(
#                 f"""
# CWE: {finding.cwe}
# Vulnerability: {finding.vulnerability}
# Severity: {finding.severity}
# Line: {finding.line}
# Description: {finding.description}
# Recommendation: {finding.recommendation}
# """
#             )

#         security_report = "\n".join(findings)

#         prompt = f"""
# You generated the following Python code:

# ```python
# {code}