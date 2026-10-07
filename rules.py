from dataclasses import dataclass
import re


@dataclass
class SecurityRule:
    rule_id: str
    pattern: str
    cwe: str
    vulnerability: str
    owasp: str
    severity: str
    description: str
    recommendation: str

    def compile(self):
        return re.compile(
            self.pattern,
            re.IGNORECASE
        )


RULES = [

    # =========================================================
    # A03 - Injection
    # =========================================================

    SecurityRule(
        rule_id="DEV-A03-001",
        pattern=r"\beval\s*\(",
        cwe="CWE-95",
        vulnerability="Eval Injection",
        owasp="A03:2021-Injection",
        severity="CRITICAL",
        description=(
            "eval() dynamically evaluates Python expressions "
            "and can execute attacker-controlled code."
        ),
        recommendation=(
            "Avoid eval(). Use explicit parsing, validation, "
            "or an allow-list of supported operations."
        )
    ),

    SecurityRule(
        rule_id="DEV-A03-002",
        pattern=r"\bexec\s*\(",
        cwe="CWE-95",
        vulnerability="Dynamic Code Execution",
        owasp="A03:2021-Injection",
        severity="CRITICAL",
        description=(
            "exec() dynamically executes Python code."
        ),
        recommendation=(
            "Avoid exec() when processing untrusted input."
        )
    ),

    SecurityRule(
        rule_id="DEV-A03-003",
        pattern=r"\bos\.system\s*\(",
        cwe="CWE-78",
        vulnerability="OS Command Injection",
        owasp="A03:2021-Injection",
        severity="CRITICAL",
        description=(
            "os.system() executes operating-system commands "
            "and may become vulnerable when input is attacker-controlled."
        ),
        recommendation=(
            "Avoid os.system(). Prefer subprocess with shell=False "
            "and validate command arguments."
        )
    ),

    SecurityRule(
        rule_id="DEV-A03-004",
        pattern=(
            r"\bsubprocess\."
            r"(run|call|Popen|check_output|check_call)"
            r"\s*\("
        ),
        cwe="CWE-78",
        vulnerability="Potential Command Injection",
        owasp="A03:2021-Injection",
        severity="HIGH",
        description=(
            "Subprocess execution can become dangerous when "
            "command arguments originate from untrusted input."
        ),
        recommendation=(
            "Use shell=False and pass arguments as a list. "
            "Validate externally supplied arguments."
        )
    ),

    SecurityRule(
        rule_id="DEV-A03-005",
        pattern=r"\bsubprocess\.(run|call|Popen)\s*\([^)]*shell\s*=\s*True",
        cwe="CWE-78",
        vulnerability="Shell Command Injection",
        owasp="A03:2021-Injection",
        severity="CRITICAL",
        description=(
            "subprocess execution with shell=True can interpret "
            "shell metacharacters in attacker-controlled input."
        ),
        recommendation=(
            "Use shell=False and pass command arguments as a list."
        )
    ),

    # =========================================================
    # SQL Injection
    # =========================================================

    SecurityRule(
        rule_id="DEV-A03-006",
        pattern=r"\b(cursor|connection)\.execute\s*\([^)]*\+",
        cwe="CWE-89",
        vulnerability="Potential SQL Injection",
        owasp="A03:2021-Injection",
        severity="CRITICAL",
        description=(
            "SQL execution appears to use string concatenation."
        ),
        recommendation=(
            "Use parameterized SQL queries instead of "
            "concatenating user-controlled values."
        )
    ),

    SecurityRule(
        rule_id="DEV-A03-007",
        pattern=r"\bexecute\s*\(\s*f[\"']",
        cwe="CWE-89",
        vulnerability="Potential SQL Injection",
        owasp="A03:2021-Injection",
        severity="CRITICAL",
        description=(
            "An SQL query appears to use an f-string."
        ),
        recommendation=(
            "Use parameterized queries instead of string interpolation."
        )
    ),

    # =========================================================
    # A08 - Software and Data Integrity Failures
    # =========================================================

    SecurityRule(
        rule_id="DEV-A08-001",
        pattern=r"\bpickle\.(load|loads)\s*\(",
        cwe="CWE-502",
        vulnerability="Unsafe Deserialization",
        owasp="A08:2021-Software and Data Integrity Failures",
        severity="CRITICAL",
        description=(
            "pickle deserialization can execute arbitrary code "
            "when processing malicious data."
        ),
        recommendation=(
            "Never deserialize untrusted pickle data. "
            "Prefer JSON or another safe serialization format."
        )
    ),

    SecurityRule(
        rule_id="DEV-A08-002",
        pattern=r"\byaml\.load\s*\(",
        cwe="CWE-502",
        vulnerability="Unsafe YAML Deserialization",
        owasp="A08:2021-Software and Data Integrity Failures",
        severity="HIGH",
        description=(
            "yaml.load() can deserialize unsafe YAML objects."
        ),
        recommendation=(
            "Use yaml.safe_load() for untrusted YAML."
        )
    ),

    SecurityRule(
        rule_id="DEV-A08-003",
        pattern=r"\byaml\.unsafe_load\s*\(",
        cwe="CWE-502",
        vulnerability="Unsafe YAML Deserialization",
        owasp="A08:2021-Software and Data Integrity Failures",
        severity="CRITICAL",
        description=(
            "yaml.unsafe_load() can construct arbitrary Python objects."
        ),
        recommendation=(
            "Use yaml.safe_load() for untrusted YAML."
        )
    ),

    # =========================================================
    # A07 - Identification and Authentication Failures
    # =========================================================

    SecurityRule(
        rule_id="DEV-A07-001",
        pattern=(
            r"\b(password|passwd|pwd|secret|api_key|apikey|"
            r"access_token|auth_token)"
            r"\s*=\s*[\"'][^\"']+[\"']"
        ),
        cwe="CWE-798",
        vulnerability="Hardcoded Credentials",
        owasp="A07:2021-Identification and Authentication Failures",
        severity="HIGH",
        description=(
            "A credential-like value appears to be hardcoded "
            "in the source code."
        ),
        recommendation=(
            "Store secrets in environment variables or a "
            "dedicated secret-management system."
        )
    ),

    # =========================================================
    # A05 - Security Misconfiguration
    # =========================================================

    SecurityRule(
        rule_id="DEV-A05-001",
        pattern=r"\bapp\.run\s*\([^)]*debug\s*=\s*True",
        cwe="CWE-489",
        vulnerability="Debug Mode Enabled",
        owasp="A05:2021-Security Misconfiguration",
        severity="MEDIUM",
        description=(
            "Flask debug mode can expose sensitive information "
            "and should not be enabled in production."
        ),
        recommendation=(
            "Disable debug mode in production."
        )
    ),

    # =========================================================
    # A01 - Broken Access Control
    # =========================================================

    SecurityRule(
        rule_id="DEV-A01-001",
        pattern=(
            r"request\.(args|form|json)"
            r".*\b(user|admin|role|permission)"
        ),
        cwe="CWE-862",
        vulnerability="Potential Missing Authorization",
        owasp="A01:2021-Broken Access Control",
        severity="HIGH",
        description=(
            "User-controlled authorization-related data may be "
            "used without an obvious server-side authorization check."
        ),
        recommendation=(
            "Perform authorization checks using trusted server-side "
            "identity information."
        )
    ),

    # =========================================================
    # A02 - Cryptographic Failures
    # =========================================================

    SecurityRule(
        rule_id="DEV-A02-001",
        pattern=r"\bhashlib\.md5\s*\(",
        cwe="CWE-328",
        vulnerability="Weak Cryptographic Hash",
        owasp="A02:2021-Cryptographic Failures",
        severity="MEDIUM",
        description=(
            "MD5 is cryptographically broken and should not be "
            "used for security-sensitive hashing."
        ),
        recommendation=(
            "Use SHA-256 or a modern password hashing algorithm "
            "such as Argon2, bcrypt, or scrypt."
        )
    ),

    SecurityRule(
        rule_id="DEV-A02-002",
        pattern=r"\bhashlib\.sha1\s*\(",
        cwe="CWE-328",
        vulnerability="Weak Cryptographic Hash",
        owasp="A02:2021-Cryptographic Failures",
        severity="MEDIUM",
        description=(
            "SHA-1 is considered cryptographically weak."
        ),
        recommendation=(
            "Use SHA-256 or a stronger cryptographic primitive."
        )
    ),

    # =========================================================
    # A10 - Server-Side Request Forgery
    # =========================================================

    SecurityRule(
        rule_id="DEV-A10-001",
        pattern=(
            r"\brequests\.(get|post|put|delete|patch|request)"
            r"\s*\("
        ),
        cwe="CWE-918",
        vulnerability="Potential SSRF",
        owasp="A10:2021-Server-Side Request Forgery",
        severity="HIGH",
        description=(
            "An HTTP request is made from the server. "
            "This can become SSRF when the destination is attacker-controlled."
        ),
        recommendation=(
            "Validate and allow-list destination hosts. "
            "Block requests to internal and metadata-service addresses."
        )
    ),

    # =========================================================
    # A04 - Insecure Design
    # =========================================================

    SecurityRule(
        rule_id="DEV-A04-001",
        pattern=r"\brandom\.(random|randint|choice|randrange)\s*\(",
        cwe="CWE-330",
        vulnerability="Insufficiently Random Values",
        owasp="A04:2021-Insecure Design",
        severity="MEDIUM",
        description=(
            "The random module is not designed for security-sensitive "
            "random values."
        ),
        recommendation=(
            "Use the secrets module for security-sensitive "
            "tokens, passwords, and identifiers."
        )
    )
]