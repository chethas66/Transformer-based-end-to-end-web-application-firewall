import re
from typing import Tuple, Optional
from dataclasses import dataclass


@dataclass
class FastPathResult:
    blocked: bool
    rule_name: Optional[str] = None
    matched_pattern: Optional[str] = None
    confidence: float = 1.0


class FastPathFilter:

    def __init__(self):
        self.sql_injection_patterns = [
            (r"(\bUNION\b.*\bSELECT\b)", "SQL_UNION_SELECT"),
            (r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)", "SQL_OR_TAUTOLOGY"),
            (r"(\bAND\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)", "SQL_AND_TAUTOLOGY"),
            (r"(;\s*DROP\s+TABLE)", "SQL_DROP_TABLE"),
            (r"(;\s*DELETE\s+FROM)", "SQL_DELETE"),
            (r"(;\s*UPDATE\s+.*\s+SET)", "SQL_UPDATE"),
            (r"(;\s*INSERT\s+INTO)", "SQL_INSERT"),
            (r"(--|\#|\/\*|\*\/)", "SQL_COMMENT"),
            (r"(\bEXEC\b|\bEXECUTE\b).*\(", "SQL_EXEC"),
            (r"(\bxp_cmdshell\b)", "SQL_XP_CMDSHELL"),
            (r"(WAITFOR\s+DELAY)", "SQL_TIME_BASED"),
            (r"(BENCHMARK\s*\()", "SQL_BENCHMARK"),
            (r"(SLEEP\s*\()", "SQL_SLEEP"),
        ]

        self.xss_patterns = [
            (r"<script[^>]*>.*?</script>", "XSS_SCRIPT_TAG"),
            (r"<script[^>]*>", "XSS_SCRIPT_OPEN"),
            (r"javascript:", "XSS_JAVASCRIPT_PROTOCOL"),
            (r"on\w+\s*=", "XSS_EVENT_HANDLER"),
            (r"<iframe[^>]*>", "XSS_IFRAME"),
            (r"<object[^>]*>", "XSS_OBJECT"),
            (r"<embed[^>]*>", "XSS_EMBED"),
            (r"<img[^>]*on\w+", "XSS_IMG_EVENT"),
            (r"<svg[^>]*on\w+", "XSS_SVG_EVENT"),
            (r"eval\s*\(", "XSS_EVAL"),
            (r"alert\s*\(", "XSS_ALERT"),
            (r"prompt\s*\(", "XSS_PROMPT"),
            (r"confirm\s*\(", "XSS_CONFIRM"),
            (r"document\.cookie", "XSS_COOKIE_THEFT"),
            (r"document\.write", "XSS_DOCUMENT_WRITE"),
        ]

        self.path_traversal_patterns = [
            (r"\.\./", "PATH_TRAVERSAL_DOTDOT"),
            (r"\.\.\\", "PATH_TRAVERSAL_DOTDOT_WIN"),
            (r"%2e%2e[/\\]", "PATH_TRAVERSAL_ENCODED"),
            (r"\.\.%2f", "PATH_TRAVERSAL_MIXED"),
            (r"/etc/passwd", "PATH_TRAVERSAL_PASSWD"),
            (r"c:\\windows", "PATH_TRAVERSAL_WINDOWS"),
            (r"/proc/self", "PATH_TRAVERSAL_PROC"),
        ]

        self.command_injection_patterns = [
            (r"[;&|]\s*\w+", "CMD_CHAIN"),
            (r"`.*`", "CMD_BACKTICK"),
            (r"\$\(.*\)", "CMD_SUBSTITUTION"),
            (r">\s*/dev/", "CMD_REDIRECT"),
            (r"\|\s*nc\s+", "CMD_NETCAT"),
            (r"bash\s+-[ci]", "CMD_BASH"),
            (r"wget\s+", "CMD_WGET"),
            (r"curl\s+", "CMD_CURL"),
        ]

        self.xxe_patterns = [
            (r"<!ENTITY", "XXE_ENTITY"),
            (r"<!DOCTYPE.*ENTITY", "XXE_DOCTYPE"),
            (r"SYSTEM\s+['\"]", "XXE_SYSTEM"),
            (r"PUBLIC\s+['\"]", "XXE_PUBLIC"),
        ]

        self.ssrf_patterns = [
            (r"file://", "SSRF_FILE_PROTOCOL"),
            (r"gopher://", "SSRF_GOPHER_PROTOCOL"),
            (r"dict://", "SSRF_DICT_PROTOCOL"),
            (r"localhost", "SSRF_LOCALHOST"),
            (r"127\.0\.0\.1", "SSRF_LOOPBACK"),
            (r"169\.254\.169\.254", "SSRF_AWS_METADATA"),
            (r"metadata\.google\.internal", "SSRF_GCP_METADATA"),
        ]

        self.compiled_patterns = []
        for patterns, category in [
            (self.sql_injection_patterns, "SQLi"),
            (self.xss_patterns, "XSS"),
            (self.path_traversal_patterns, "PATH_TRAVERSAL"),
            (self.command_injection_patterns, "CMD_INJECTION"),
            (self.xxe_patterns, "XXE"),
            (self.ssrf_patterns, "SSRF"),
        ]:
            for pattern, rule_name in patterns:
                self.compiled_patterns.append(
                    (re.compile(pattern, re.IGNORECASE), f"{category}:{rule_name}")
                )

    def check(self, normalized_request: str) -> FastPathResult:

        for compiled_pattern, rule_name in self.compiled_patterns:
            match = compiled_pattern.search(normalized_request)
            if match:
                return FastPathResult(
                    blocked=True,
                    rule_name=rule_name,
                    matched_pattern=match.group(0),
                    confidence=1.0
                )

        return FastPathResult(blocked=False)

    def check_headers(self, headers: dict) -> FastPathResult:
        suspicious_headers = {
            "X-Forwarded-For": [r"127\.0\.0\.1", r"localhost"],
            "User-Agent": [r"sqlmap", r"nikto", r"nmap", r"masscan"],
            "Referer": [r"<script", r"javascript:"],
        }

        for header_name, patterns in suspicious_headers.items():
            if header_name.lower() in [k.lower() for k in headers.keys()]:
                header_value = headers.get(header_name, "")
                for pattern in patterns:
                    if re.search(pattern, header_value, re.IGNORECASE):
                        return FastPathResult(
                            blocked=True,
                            rule_name=f"SUSPICIOUS_HEADER:{header_name}",
                            matched_pattern=pattern,
                            confidence=0.9
                        )

        return FastPathResult(blocked=False)


if __name__ == "__main__":
    filter = FastPathFilter()

    test_cases = [
        "GET /api/users?id=1 OR 1=1--",
        "POST /search BODY:{\"query\": \"<script>alert(1)</script>\"}",
        "GET /api/../../../etc/passwd",
        "GET /api/exec?cmd=ls; cat /etc/passwd",
        "POST /api/xml BODY:<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
        "GET /api/fetch?url=http://169.254.169.254/latest/meta-data/",
        "GET /api/normal?id=<ID>&user=<EMAIL>",
    ]

    print("=== Fast-Path Filter Test Results ===\n")
    for i, test_request in enumerate(test_cases, 1):
        result = filter.check(test_request)
        print(f"Test {i}: {test_request[:60]}...")
        if result.blocked:
            print(f"  ⚠️  BLOCKED by rule: {result.rule_name}")
            print(f"  Pattern matched: {result.matched_pattern}")
        else:
            print(f"  ✓ Passed fast-path")
        print()
