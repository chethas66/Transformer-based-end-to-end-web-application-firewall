import re
import base64
import urllib.parse
from typing import Dict, Any, Tuple
import json


class HTTPRequestNormalizer:

    def __init__(self):
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.uuid_pattern = re.compile(
            r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        )
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.session_pattern = re.compile(r'(session|sess|token|jwt)[:=][^\s;&]+', re.IGNORECASE)
        self.numeric_id_pattern = re.compile(r'\b\d{6,}\b')
        self.timestamp_pattern = re.compile(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}')

    def decode_encodings(self, text: str) -> str:
        decoded = text

        try:
            decoded = urllib.parse.unquote(decoded)
        except Exception:
            pass

        try:
            decoded = urllib.parse.unquote_plus(decoded)
        except Exception:
            pass

        base64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        potential_b64 = base64_pattern.findall(decoded)

        for b64_str in potential_b64:
            if len(b64_str) >= 16:
                try:
                    decoded_bytes = base64.b64decode(b64_str)
                    decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                    if decoded_text.isprintable():
                        decoded = decoded.replace(b64_str, decoded_text)
                except Exception:
                    pass

        return decoded

    def canonicalize(self, text: str) -> str:
        canonical = text

        canonical = self.ip_pattern.sub('<IP>', canonical)
        canonical = self.uuid_pattern.sub('<UUID>', canonical)
        canonical = self.email_pattern.sub('<EMAIL>', canonical)
        canonical = self.session_pattern.sub(r'\1=<SESSION>', canonical)
        canonical = self.numeric_id_pattern.sub('<ID>', canonical)
        canonical = self.timestamp_pattern.sub('<TIMESTAMP>', canonical)

        canonical = re.sub(r'\s+', ' ', canonical)
        canonical = canonical.strip()

        return canonical

    def normalize_http_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: str = ""
    ) -> Tuple[str, Dict[str, Any]]:

        decoded_path = self.decode_encodings(path)
        decoded_body = self.decode_encodings(body)

        canonical_path = self.canonicalize(decoded_path)
        canonical_body = self.canonicalize(decoded_body)

        important_headers = {}
        for key in ['user-agent', 'referer', 'cookie', 'content-type', 'authorization']:
            if key in headers:
                decoded_header = self.decode_encodings(headers[key])
                important_headers[key] = self.canonicalize(decoded_header)

        normalized_request = f"{method.upper()} {canonical_path}"

        if canonical_body:
            normalized_request += f" BODY:{canonical_body}"

        if important_headers:
            headers_str = " ".join([f"{k}:{v}" for k, v in important_headers.items()])
            normalized_request += f" HEADERS:{headers_str}"

        metadata = {
            "original_path": path,
            "decoded_path": decoded_path,
            "canonical_path": canonical_path,
            "has_body": bool(body),
            "body_length": len(body),
            "header_count": len(headers)
        }

        return normalized_request, metadata

    def parse_nginx_log(self, log_line: str) -> Dict[str, Any]:
        nginx_pattern = re.compile(
            r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<path>[^\s]+) HTTP/[^"]+" '
            r'(?P<status>\d+) (?P<size>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )

        match = nginx_pattern.match(log_line)
        if not match:
            return None

        data = match.groupdict()

        return {
            "source_ip": data["ip"],
            "timestamp": data["timestamp"],
            "method": data["method"],
            "path": data["path"],
            "status": int(data["status"]),
            "size": int(data["size"]),
            "headers": {
                "referer": data["referer"],
                "user-agent": data["user_agent"]
            }
        }

    def parse_apache_log(self, log_line: str) -> Dict[str, Any]:
        apache_pattern = re.compile(
            r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<path>[^\s]+) HTTP/[^"]+" '
            r'(?P<status>\d+) (?P<size>[\d-]+)'
        )

        match = apache_pattern.match(log_line)
        if not match:
            return None

        data = match.groupdict()

        return {
            "source_ip": data["ip"],
            "timestamp": data["timestamp"],
            "method": data["method"],
            "path": data["path"],
            "status": int(data["status"]),
            "size": int(data["size"]) if data["size"] != "-" else 0,
            "headers": {}
        }


if __name__ == "__main__":
    normalizer = HTTPRequestNormalizer()

    test_cases = [
        {
            "method": "GET",
            "path": "/api/users/12345678/profile?token=abc123",
            "headers": {"user-agent": "Mozilla/5.0", "cookie": "session=xyz789"},
            "body": ""
        },
        {
            "method": "POST",
            "path": "/search",
            "headers": {"content-type": "application/json"},
            "body": '{"query": "admin OR 1=1-- ", "email": "test@example.com"}'
        },
        {
            "method": "GET",
            "path": "/api/data?id=%3Cscript%3Ealert(1)%3C/script%3E",
            "headers": {},
            "body": ""
        }
    ]

    print("=== HTTP Request Normalization Examples ===\n")
    for i, test in enumerate(test_cases, 1):
        normalized, metadata = normalizer.normalize_http_request(
            test["method"], test["path"], test["headers"], test["body"]
        )
        print(f"Test Case {i}:")
        print(f"Original: {test['method']} {test['path']}")
        print(f"Normalized: {normalized}")
        print(f"Metadata: {json.dumps(metadata, indent=2)}")
        print()
