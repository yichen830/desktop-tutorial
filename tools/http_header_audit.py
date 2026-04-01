#!/usr/bin/env python3
import argparse
import json
import socket
import ssl
from urllib.parse import urlparse
from urllib.request import Request, urlopen

SECURITY_HEADERS = {
    "strict-transport-security": "建议 HTTPS 站点启用 HSTS",
    "content-security-policy": "建议配置 CSP 减少 XSS 与内容注入风险",
    "x-content-type-options": "建议启用 nosniff",
    "x-frame-options": "建议限制页面被嵌入",
    "referrer-policy": "建议明确来源引用策略",
    "permissions-policy": "建议收敛浏览器能力暴露",
}


def fetch_headers(url: str, timeout: int) -> tuple[int, dict[str, str]]:
    request = Request(url, headers={"User-Agent": "zerotrace-header-audit/1.0"})
    with urlopen(request, timeout=timeout) as response:
        headers = {key.lower(): value for key, value in response.headers.items()}
        return response.getcode(), headers


def inspect_tls(hostname: str, port: int, timeout: int) -> dict[str, str]:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert = tls_sock.getpeercert()
            cipher = tls_sock.cipher()
            return {
                "tls_version": tls_sock.version() or "unknown",
                "cipher": cipher[0] if cipher else "unknown",
                "issuer": str(cert.get("issuer", "unknown")),
                "subject": str(cert.get("subject", "unknown")),
            }


def audit(url: str, timeout: int) -> dict:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("仅支持 http/https URL")

    status_code, headers = fetch_headers(url, timeout)
    missing_headers = [
        {"header": header, "recommendation": recommendation}
        for header, recommendation in SECURITY_HEADERS.items()
        if header not in headers
    ]

    result = {
        "url": url,
        "status_code": status_code,
        "headers": headers,
        "missing_security_headers": missing_headers,
    }

    if parsed.scheme == "https":
        result["tls"] = inspect_tls(parsed.hostname or "", parsed.port or 443, timeout)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP 头部与 TLS 基线审计工具")
    parser.add_argument("url", help="目标 URL，例如 https://example.com")
    parser.add_argument("--timeout", type=int, default=8, help="网络超时秒数")
    args = parser.parse_args()

    report = audit(args.url, args.timeout)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
