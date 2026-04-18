import httpx
import asyncio
from typing import Dict, Any
import json


class WAFClient:

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=30.0)

    async def analyze_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: str = "",
        source_ip: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        response = await self.client.post(
            f"{self.base_url}/api/waf/analyze",
            json={
                "method": method,
                "path": path,
                "headers": headers,
                "body": body,
                "source_ip": source_ip
            }
        )
        response.raise_for_status()
        return response.json()

    async def health_check(self) -> Dict[str, Any]:
        response = await self.client.get(f"{self.base_url}/api/waf/health")
        response.raise_for_status()
        return response.json()

    async def get_statistics(self) -> Dict[str, Any]:
        response = await self.client.get(f"{self.base_url}/api/waf/stats")
        response.raise_for_status()
        return response.json()

    async def submit_feedback(
        self,
        request_id: str,
        corrected_label: str,
        notes: str = None
    ) -> Dict[str, Any]:
        response = await self.client.post(
            f"{self.base_url}/api/waf/feedback",
            json={
                "request_id": request_id,
                "corrected_label": corrected_label,
                "notes": notes
            }
        )
        response.raise_for_status()
        return response.json()

    async def update_config(
        self,
        mode: str = None,
        block_threshold: float = None,
        flag_threshold: float = None
    ) -> Dict[str, Any]:
        params = {}
        if mode:
            params["mode"] = mode
        if block_threshold is not None:
            params["block_threshold"] = block_threshold
        if flag_threshold is not None:
            params["flag_threshold"] = flag_threshold

        response = await self.client.post(
            f"{self.base_url}/api/waf/config",
            params=params
        )
        response.raise_for_status()
        return response.json()

    async def close(self):
        await self.client.aclose()


async def test_benign_requests():
    client = WAFClient()

    benign_tests = [
        {
            "name": "Normal API Request",
            "method": "GET",
            "path": "/api/users/12345",
            "headers": {"user-agent": "Mozilla/5.0"},
            "body": ""
        },
        {
            "name": "Search Query",
            "method": "POST",
            "path": "/api/search",
            "headers": {"content-type": "application/json"},
            "body": '{"query": "laptop computers", "category": "electronics"}'
        },
        {
            "name": "User Login",
            "method": "POST",
            "path": "/api/auth/login",
            "headers": {"content-type": "application/json"},
            "body": '{"email": "user@example.com", "password": "SecurePass123!"}'
        }
    ]

    print("🧪 Testing Benign Requests\n")
    print("=" * 80)

    for test in benign_tests:
        result = await client.analyze_request(
            method=test["method"],
            path=test["path"],
            headers=test["headers"],
            body=test["body"],
            source_ip="192.168.1.100"
        )

        print(f"\n✅ {test['name']}")
        print(f"   Action: {result['action']}")
        print(f"   Threat Level: {result['threat_level']}")
        print(f"   Confidence: {result['confidence']:.3f}")
        print(f"   Latency: {result['latency_ms']:.2f}ms")
        print(f"   Reasoning: {result['reasoning']}")

    await client.close()


async def test_malicious_requests():
    client = WAFClient()

    malicious_tests = [
        {
            "name": "SQL Injection (Union-based)",
            "method": "GET",
            "path": "/api/users?id=1 UNION SELECT username,password FROM users--",
            "headers": {},
            "body": ""
        },
        {
            "name": "XSS Attack",
            "method": "POST",
            "path": "/api/comment",
            "headers": {"content-type": "application/json"},
            "body": '{"text": "<script>alert(document.cookie)</script>"}'
        },
        {
            "name": "Path Traversal",
            "method": "GET",
            "path": "/api/file?path=../../../etc/passwd",
            "headers": {},
            "body": ""
        },
        {
            "name": "Command Injection",
            "method": "POST",
            "path": "/api/exec",
            "headers": {"content-type": "application/json"},
            "body": '{"cmd": "ls; cat /etc/passwd"}'
        },
        {
            "name": "XXE Attack",
            "method": "POST",
            "path": "/api/xml",
            "headers": {"content-type": "application/xml"},
            "body": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>'
        }
    ]

    print("\n🔴 Testing Malicious Requests\n")
    print("=" * 80)

    for test in malicious_tests:
        result = await client.analyze_request(
            method=test["method"],
            path=test["path"],
            headers=test["headers"],
            body=test["body"],
            source_ip="10.0.0.50"
        )

        print(f"\n⚠️  {test['name']}")
        print(f"   Action: {result['action']}")
        print(f"   Threat Level: {result['threat_level']}")
        print(f"   Confidence: {result['confidence']:.3f}")
        print(f"   Fast-Path: {'Yes' if result['fast_path_blocked'] else 'No'}")
        if result['fast_path_rule']:
            print(f"   Rule: {result['fast_path_rule']}")
        print(f"   Transformer: {result['transformer_prediction']} ({result['transformer_confidence']:.3f})")
        print(f"   Latency: {result['latency_ms']:.2f}ms")
        print(f"   Reasoning: {result['reasoning']}")

    await client.close()


async def test_polyglot_attacks():
    client = WAFClient()

    polyglot_tests = [
        {
            "name": "SQLi + XSS Polyglot",
            "method": "GET",
            "path": "/api/search?q='><script>alert(1)</script> OR 1=1--",
            "headers": {},
            "body": ""
        },
        {
            "name": "Encoded SQLi",
            "method": "GET",
            "path": "/api/data?id=%27%20OR%20%271%27%3D%271",
            "headers": {},
            "body": ""
        },
        {
            "name": "Mixed Case Evasion",
            "method": "GET",
            "path": "/api/users?id=1 UnIoN SeLeCt * FrOm users--",
            "headers": {},
            "body": ""
        }
    ]

    print("\n🎭 Testing Polyglot & Obfuscated Attacks\n")
    print("=" * 80)

    for test in polyglot_tests:
        result = await client.analyze_request(
            method=test["method"],
            path=test["path"],
            headers=test["headers"],
            body=test["body"],
            source_ip="203.0.113.42"
        )

        print(f"\n⚠️  {test['name']}")
        print(f"   Action: {result['action']}")
        print(f"   Normalized: {result['normalized_request'][:100]}...")
        print(f"   Detection: {result['reasoning']}")
        print(f"   Latency: {result['latency_ms']:.2f}ms")

    await client.close()


async def test_performance_benchmark():
    client = WAFClient()

    test_request = {
        "method": "GET",
        "path": "/api/products?category=electronics&page=1",
        "headers": {"user-agent": "BenchmarkClient/1.0"},
        "body": "",
        "source_ip": "192.168.1.200"
    }

    print("\n⚡ Performance Benchmark\n")
    print("=" * 80)

    iterations = 100
    latencies = []

    print(f"Running {iterations} requests...")

    for i in range(iterations):
        result = await client.analyze_request(**test_request)
        latencies.append(result['latency_ms'])

        if (i + 1) % 20 == 0:
            print(f"  Progress: {i + 1}/{iterations}")

    import statistics

    print(f"\n📊 Results:")
    print(f"   Mean Latency:   {statistics.mean(latencies):.2f}ms")
    print(f"   Median Latency: {statistics.median(latencies):.2f}ms")
    print(f"   Min Latency:    {min(latencies):.2f}ms")
    print(f"   Max Latency:    {max(latencies):.2f}ms")
    print(f"   Std Dev:        {statistics.stdev(latencies):.2f}ms")

    await client.close()


async def main():
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║       TRANSFORMER-BASED WAF - CLIENT EXAMPLES           ║")
    print("╚══════════════════════════════════════════════════════════╝\n")

    client = WAFClient()

    try:
        health = await client.health_check()
        print(f"✅ WAF Status: {health['status']}")
        print(f"   Model Loaded: {health['model_loaded']}")
        print(f"   Mode: {health['mode']}")
        print(f"   Version: {health['version']}\n")
    except Exception as e:
        print(f"❌ WAF not available: {e}")
        print("Please start the WAF API first: python waf_api.py\n")
        return

    await client.close()

    await test_benign_requests()
    await test_malicious_requests()
    await test_polyglot_attacks()
    await test_performance_benchmark()

    print("\n✅ All tests completed!\n")


if __name__ == "__main__":
    asyncio.run(main())
