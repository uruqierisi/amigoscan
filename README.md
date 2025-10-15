# AMIGOS — Pentest Scanner

A lightweight, asynchronous OWASP-focused pentest scanner with three scan intensities (light / medium / deep).  
Designed for red-teamers and security researchers who want fast reconnaissance with minimal dependencies.

> 🔐 **Ethical use only** — run this tool only against systems you own or have explicit authorization to test.

---

## Features

- Three scan intensities:
  - **`--light`** — passive checks: headers, cookies, CORS
  - **`--medium`** — includes common file discovery and basic parameter tampering (XSS checks)
  - **`--deep`** — aggressive checks including deeper XSS/SQLi tampering
- Asynchronous, concurrent scanning (fast)
- Human-readable CLI summary + full JSON artifact output
- Small runtime dependency footprint (Python + aiohttp + termcolor)
- Minimal UI noise — suitable for field usage and automation

---

## Quick Start (Debian / Kali / Ubuntu)

```bash
# system deps
sudo apt update
sudo apt install -y python3 python3-pip git

# clone and install
git clone https://github.com/uruqierisi/amigoscan.git
cd amigoscan
pip install -r requirements.txt

# make the script executable (if needed)
chmod +x amigos.py

# verify
./amigos.py --help
```
# Install dependencies first
```bash
pip3 install -r requirements.txt

# Download script directly (raw file link)
curl -O https://raw.githubusercontent.com/uruqierisi/amigoscan/main/amigos.py

# Make executable
chmod +x amigos.py
```
# Usage Examples
```bash
# Passive scan (light)
./amigos.py example.com --light

# Medium scan + save JSON
./amigos.py https://signup.target.com --medium --output results/target_signup.json

# Deep scan (single URL with params)
./amigos.py --deep "http://testphp.vulnweb.com/artists.php?artist=1"

# Batch scan (file input)
# Create domains.txt with one URL per line, then:

./amigos.py --file domains.txt --medium --output all-domains-report.json
```
Terminal Example
```bash
# Command:
./amigos.py https://signup.target.com --medium --output results/target_signup.json
```
Example CLI output (sample)
```bash
[*] Starting Pentest Scan...
✅ SCAN REPORT SUMMARY
============================================================
🎯 Websites Scanned: 1
🔎 Total Issues Identified: 3

🔐 CRITICAL ISSUES DETECTED:
 [https://signup.target.com] ⚡️ XSS Triggered (2 parameters affected)
     Manually verify payload such as '<script>alert(1)</script>' in URL params.
 [https://signup.target.com] 🌐 Wildcard Origin With Credentials Allowed!
     Check Access-Control-Allow-Origin header.

🟡 ACTIONABLE FINDINGS - VERIFY MANUALLY
 [https://signup.target.com] 200 → .git/
     Use wget/curl to download and inspect: https://signup.target.com/.git/
 [https://signup.target.com] 🔁 TRACE method allowed - HTTP verb tampering possible.
 [https://signup.target.com] ⚠ Cookie Vulnerability Detected
      Parameter Name: 'sessionID', Reason: Missing Secure

📄 Raw scan saved to 'results/target_signup.json'.
```
Output & JSON Report
When --output <file> is provided, a JSON file is written containing full details: timestamps, findings, request/response snippets and more.

Example JSON keys (actual structure may vary):
```bash
{
  "target": "https://signup.target.com",
  "scan_type": "medium",
  "checked_at": "2025-01-01T12:00:00Z",
  "findings": [
    {
      "type": "xss_violations_found",
      "description": "Parameter-based XSS indicators identified",
      "matches": [ /* ... */ ]
    }
  ],
  "raw": { "requests": [ /* request/response objects */ ] }
}
```
Designed For Security Research & Educational Purposes. Unauthorized usage against third-party infrastructure may carry legal consequences.
