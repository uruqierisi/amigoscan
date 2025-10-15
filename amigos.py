#!/usr/bin/env python3
"""
AMIGOS PENTEST SCANNER v1 – Light, Medium, Deep Modes for Ethical Web Scanning.

Author: kodeksi,snowwww
Use Only With Explicit Authorization.
"""

import argparse
import asyncio
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from typing import List, Dict, Any

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

try:
    from termcolor import colored
except ImportError:
    def colored(text, *args, **kwargs):
        return text

# -- Global Configuration Constants --

HEADERS_TO_CHECK = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

XSS_PAYLOADS = [
    "<script>alert(document.domain)</script>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)"
]

SQLI_PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1",
    "UNION SELECT NULL,NULL--",
]

CMDI_PAYLOADS = [
    ";ls",
    ";id",
    "|cat /etc/passwd",
]

# Dynamic depth selection sets path targets
SENSITIVE_FILE_MAP = {
    "light": ["robots.txt", "sitemap.xml"],
    "medium": [
        "robots.txt",
        "sitemap.xml",
        ".git/",
        ".env",
        "config.php",
        "wp-config.php"
    ],
    "deep": [
        "robots.txt",
        "sitemap.xml",
        ".git/",
        ".env",
        ".DS_Store",
        "config.php",
        "wp-config.php",
        "backup.sql.gz",
        "composer.lock"
    ]
}


def parse_cookies(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    cookies = []
    raw_cookies = headers.get("set-cookie")
    if raw_cookies:
        parts = raw_cookies.split(",")
        for part in parts:
            kv, *attrs = part.split(";")
            keyval = kv.split("=")[0]
            cookie_entry = {
                "key": keyval,
                "has_secure": "secure" in [a.strip().lower() for a in attrs],
                "has_httponly": "httponly" in [a.strip().lower() for a in attrs],
            }
            cookies.append(cookie_entry)
    return cookies


async def fetch(session: aiohttp.ClientSession, method: str, url: str, allow_redirects=True, timeout=10, data=None, headers=None):
    real_timeout = ClientTimeout(total=timeout)
    try:
        kwargs = dict(
            allow_redirects=allow_redirects,
            timeout=real_timeout
        )
        if data:
            kwargs['data'] = data
        if headers:
            kwargs['headers'] = headers

        async with session.request(method, url, **kwargs) as resp:
            text = None
            limit = 200_000
            if resp.content_length is None or (resp.content_length and resp.content_length < limit):
                try:
                    text = await resp.text(errors="ignore")
                except:
                    pass
            return {
                "status": resp.status,
                "url": str(resp.url),
                "headers": {k.lower(): v for k,v in resp.headers.items()},
                "text_snippet": text[:limit] if text else None,
                "method_used": method,
                "redirected_from": None
            }
    except Exception as e:
        return {"error": str(e), "method_used": method, "url": url}


async def test_param_tampering(session, base_url, payloads):
    findings = []
    parsed = urlparse(base_url)
    query = parsed.query

    if not query:
        return []

    base_params = parse_qs(query)
    clean_params = {k: v[0] if len(v)==1 else v for k,v in base_params.items()}

    for key in clean_params:
        for payload in payloads:
            mutated = dict(clean_params)
            mutated[key] = payload
            qs = urlencode(mutated, doseq=True)
            test_url = parsed._replace(query=qs).geturl()

            res = await fetch(session, "GET", test_url, timeout=5)
            content_snip = res.get("text_snippet")

            if content_snip and any(pchunk in content_snip for pchunk in payload.split()):
                findings.append({
                    "param_triggered": key,
                    "payload_used": payload,
                    "url_tested": test_url,
                    "response_len": len(content_snip)
                })
                break  # stop after successful injection test per key

    return findings


async def scan_target(session, base_url, semaphore,
                      attack_mode: bool = False, level='medium'):
    async with semaphore:
        base_url = base_url if base_url.startswith(("http://", "https://")) else f"https://{base_url}"
        out = {
            "target": base_url,
            "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "findings": [],
            "scan_type": "passive" if not attack_mode else level,
            "details": {}
        }

        parsed = urlparse(base_url)
        host = parsed.netloc.split(':')[0]

        # Base Page Response Analysis
        base_resp = await fetch(session, "GET", base_url, timeout=10)
        if 'error' in base_resp:
            out['findings'].append({'type': 'connect_error', 'message': 'Failed to connect.', 'details': base_resp})
            return out

        base_headers = base_resp['headers']
        response_text = base_resp.get("text_snippet", "")

        # Basic Security Headers Check
        missing_security_headers = [h for h in HEADERS_TO_CHECK if h not in base_headers]
        if missing_security_headers:
            out['findings'].append({
                'type': 'security_headers_missing',
                'description': 'Security headers are partially or completely absent.',
                'headers_missing': missing_security_headers
            })

        acao = base_headers.get("access-control-allow-origin")
        acac = base_headers.get("access-control-allow-credentials")
        if acao and acao == "*" and acac == "true":
            out["findings"].append({
                "type": "cors_wildcard_origin",
                "description": "Access-Control-Allow-Origin set to wildcard '*' AND credentials allowed!",
            })

        # Cookies analysis
        cookies = parse_cookies(base_headers)
        for c in cookies:
            if not (c["has_secure"] and c["has_httponly"]):
                out["findings"].append({
                    "type": "cookie_vuln",
                    "description": "Vulnerable HTTP Cookie detected",
                    "cookie_details": c
                })

        # Server banner check
        server_banner = base_headers.get("server")
        if server_banner:
            out["findings"].append({
                "type": "server_banner_detected",
                "description": f"Insecure exposure of backend technology",
                "banner": server_banner
            })

        # Common File Checks Based On Scan Level
        selected_paths = SENSITIVE_FILE_MAP[level]
        seen_files = set()
        for path in selected_paths:
            file_res = await fetch(session, 'GET', urljoin(base_url, path))
            status = file_res.get('status')
            if status and status < 400:
                sample = file_res.get('text_snippet')[:150] + '...' if file_res.get('text_snippet') else '<empty>'
                out['findings'].append({
                    "type": "exposed_sensitive_file",
                    "description": "Exposed development or configuration resource",
                    "path": path,
                    "status_code": status,
                    "sample_excerpt": sample
                })
                seen_files.add(path)

        # Trace Method Check
        trace_check = await fetch(session, "TRACE", base_url)
        if trace_check.get('status', 0) == 200:
            out['findings'].append({
                "type": "trace_method_enabled",
                "description": "HTTP TRACE method accepted - possible vulnerability",
                "status_code_returned": trace_check['status'],
                "response_size": len(trace_check.get('text_snippet',''))
            })

        # XSS Attempt in aggressive mode
        if attack_mode:
            xss_violations = await test_param_tampering(session, base_url, XSS_PAYLOADS)
            if xss_violations:
                out['findings'].append({
                    "type": "xss_violations_found",
                    "description": "Parameter-based XSS indicators identified",
                    "matches": xss_violations
                })

            # Only run SQLi testing in deepest level modes to avoid accidental false positives
            if level == "deep":
                sqli_attempts = await test_param_tampering(session, base_url, SQLI_PAYLOADS)
                if sqli_attempts:
                    out["findings"].append({
                        "type": "sql_injection_indicators",
                        "description": "Potential SQL Injection pattern matched in query parameters",
                        "matches": sqli_attempts
                    })

        return out


async def run_scanner(urls: List[str], concurrency: int = 10, timeout: int = 20,
                      attack_mode: bool = False, level: str = 'medium'):
    connector = aiohttp.TCPConnector(limit_per_host=concurrency, ssl=False)
    sem = asyncio.Semaphore(concurrency)
    timeout_config = ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout_config) as session:
        tasks = [scan_target(session, u, sem, attack_mode=attack_mode, level=level) for u in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    return results


def print_summary(reports):
    high_risk = []
    medium_risk = []

    for report in reports:
        if isinstance(report, Exception):
            continue

        findings = report.get("findings", [])
        site = report.get("target", "Unknown target")

        for finding in findings:
            typ = finding["type"]
            desc = finding.get("description", "")
            extras = {k: v for k, v in finding.items() if k not in ['type', 'description']}
            entry = {"site": site, "type": typ, "desc": desc, "extras": extras}

            # Filter only actionable findings
            if typ in ['cors_wildcard_origin', 'xss_violations_found', 'sql_injection_indicators']:
                high_risk.append(entry)
            elif typ in ['exposed_sensitive_file', 'trace_method_enabled', 'cookie_vuln']:
                medium_risk.append(entry)

    print("\n✅ SCAN REPORT SUMMARY")
    print("="*60)
    print(f"🎯 Websites Scanned: {len(reports)}")
    print(f"🔎 Total Issues Identified: {len(high_risk)+len(medium_risk)}\n")

    if high_risk:
        print(colored("🔐 CRITICAL ISSUES DETECTED:", "red"))
        for hr in high_risk:
            site = hr['site']
            typ = hr['type']
            desc = hr['desc']

            if typ == 'xss_violations_found':
                count = len(hr['extras']['matches'])
                print(colored(f" [{site}] ⚡️ XSS Triggered ({count} parameters affected)", "red"))
                print(f"     Manually verify payload such as '<script>alert(1)</script>' in URL params.")
            elif typ == 'sql_injection_indicators':
                count = len(hr['extras']['matches'])
                print(colored(f" [{site}] ⛏️ Potential SQLi Found ({count} entries)", "red"))
                print(f"     Validate with tools like 'sqlmap' against query parameters.")
            elif typ == 'cors_wildcard_origin':
                print(colored(f" [{site}] 🌐 Wildcard Origin With Credentials Allowed!", "red"))
                print("     Check Access-Control-Allow-Origin header.")

    if medium_risk:
        printed_already = set()
        print(colored("\n🟡 ACTIONABLE FINDINGS - VERIFY MANUALLY", "yellow"))

        for mid in medium_risk:
            typ = mid['type']
            site = mid['site']
            desc = mid['desc']
            info = mid['extras']

            if typ == "exposed_sensitive_file" and info['path'] not in printed_already:
                path = info['path']
                stat = info['status_code']
                print(colored(f" [{site}] {stat} → {path}", "yellow"))
                print(f"     Use wget/curl to download and inspect: {site}/{path}")
                printed_already.add(path)

            elif typ == "trace_method_enabled":
                print(colored(f" [{site}] 🔁 TRACE method allowed - HTTP verb tampering possible.", "yellow"))
                print("     Send custom trace requests through netcat/telnet")

            elif typ == "cookie_vuln":
                cookie = info['cookie_details']['key']
                has_sec = info['cookie_details']['has_secure']
                has_ht = info['cookie_details']['has_httponly']
                reason = "Missing HttpOnly" if not has_ht else ("Missing Secure" if not has_sec else "")

                print(colored(f" [{site}] ⚠ Cookie Vulnerability Detected", "yellow"))
                print(f"      Parameter Name: '{cookie}', Reason: {reason}")

    if not medium_risk and not high_risk:
        print(colored("[✓] No exploitable weaknesses found.", "green"))


def parse_input_file(filepath):
    lines = []
    with open(filepath, "r") as f:
        lines = [l.strip() for l in f.readlines() if not l.startswith("#") and l.strip()]
    return lines


def main():
    parser = argparse.ArgumentParser(
        description="AMIGOS PENTEST SCANNER v1 - Light, Medium, Deep Modes for Ethical Web Scanning",
        epilog="Use Only With Explicit Authorization. Unauthorized usage may carry legal consequences."
    )
    parser.add_argument("urls", nargs='*', help="URLs to scan.")
    parser.add_argument("--file", help="Path to txt file with list of domains.")
    parser.add_argument("--concurrency", type=int, default=8, help="Number of concurrent requests (default: 8)")
    parser.add_argument("--timeout", type=int, default=20, help="Request timeout in seconds (default: 20)")
    parser.add_argument("--output", help="File to dump full detailed report in JSON format.")
    
    # Depth control switches
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--light', action='store_true', help='Passive checks only: headers, cookies, CORS')
    group.add_argument('--medium', action='store_true', help='Standard scan plus XSS and common files')
    group.add_argument('--deep', action='store_true', help='Intensive probing including SQLi attempts')
    group.add_argument('--attack-mode', action='store_true', help='Attack active scan(aggressive scanning)')

    args = parser.parse_args()

    # Resolve level
    level = 'medium'
    if args.light:
        level = 'light'
    elif args.deep:
        level = 'deep'
    elif args.attack_mode:
        level = 'medium'  # attack mode is medium intensity with aggressive tests

    attack = level != 'light' or args.attack_mode

    urls = []
    if args.file:
        urls = parse_input_file(args.file)
    elif args.urls:
        urls = args.urls
    else:
        parser.print_help()
        exit(1)

    print(colored("[*] Starting Pentest Scan...", "blue"))
    try:
        results = asyncio.run(run_scanner(urls,
                                          concurrency=args.concurrency,
                                          timeout=args.timeout,
                                          attack_mode=attack,
                                          level=level))

        print_summary(results)

        if args.output:
            with open(args.output, "w") as fd:
                json.dump(results, fd, indent=2)
            print(colored(f"\n📄 Raw scan saved to '{args.output}'.", "blue"))

    except KeyboardInterrupt:
        print(colored("\n[-] Scan interrupted.", "red"))
        sys.exit(130)


if __name__ == "__main__":
    main()
