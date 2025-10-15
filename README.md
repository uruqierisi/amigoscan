# Pentest Scanner — README + GitHub Pages

> A lightweight, modular OWASP-focused scanner supporting light/medium/deep scan intensity. Built for red team practitioners needing fast reconnaissance without excessive tool overhead.

**🔐 For ethical use only — ensure authorized access prior to deployment.**

---

## ⚙️ Features Overview

**Scan Levels:**

* 🟢 `--light`: Basic header checks, cookie parsing, CORS detection
* 🟡 `--medium`: Adds `.env`, `.git`, XSS payload injection checks
* 🔴 `--deep`: Full XSS/SQLi form tampering simulations, advanced leak tracing

**🧾 Output Highlights:**

* Human-readable CLI summaries highlighting actionable findings
* Full JSON artifacts preserved in background
* Minimal UI noise – optimized for field usage

**💻 Lightweight:**

* Asynchronous design (fast concurrent scanning)
* Low runtime dependency footprint (Python only)

---

## 🧰 Installation Guide (Debian / Kali Linux)

```bash
sudo apt update
sudo apt install python3 python3-pip git -y


#  Clone repo (recommended for full project)
git clone https://github.com/uruqierisi/AMIGOS-Pentest-Scanner-Ethical-Reconnaissance-Framework.git
cd pentest-scanner
pip install -r requirements.txt
```

**Requires:** Python ≥ 3.8

---

## 🚀 Test it works

```bash
./pentest_scanner.py --help
```

Alternatively:

```bash
git clone https://github.com/uruqierisi/AMIGOS-Pentest-Scanner-Ethical-Reconnaissance-Framework.git
cd pentest-scanner
pip install -r requirements.txt
```

---

## 🚀 Usage Examples

**✅ Quick Passive Check**

```bash
./pentest_scanner.py example.com --light
# 🔄 Medium-Level Discovery + Payload Testing
```

**Medium scan with JSON output**

```bash
./pentest_scanner.py https://signup.target.com --medium --output results/scans/target_signup.json
# ⚡ Deep Dive Into Forms / XSS Paths
```

**Deep scan (single URL)**

```bash
./pentest_scanner.py --deep "http://testphp.vulnweb.com/artists.php?artist=1"
# 📂 List-Based Batch Scan
```

**Batch scan (file input)**

Create `domains.txt` containing one URL per line, for example:

```
https://app.example.com
http://shop.example.org/test?search=admin
...
```

Then run:

```bash
./pentest_scanner.py --file domains.txt --medium --output all-domains-report.json
# 🧪 Sample Output Summary
```

---

## ✅ SCAN REPORT SUMMARY (example)

* 🎯 **Websites Scanned:** 1
* 🔎 **Total Issues Identified:** 3

**🔐 CRITICAL ISSUES DETECTED:** `[https://signup.target.com]`

* ⚡️ **XSS Triggered** (2 parameters affected) — Manually verify payload such as `'<script>alert(1)</script>'` in URL params.
* 🌐 **Wildcard Origin With Credentials Allowed** — risky CORS configuration.

**🟡 ACTIONABLE FINDINGS - VERIFY MANUALLY**

* `https://signup.target.com` — `200` → `.git/` accessible. Use `wget/curl` to download and inspect: `https://signup.target.com/.git/`
* `https://signup.target.com` — `TRACE` method allowed — HTTP verb tampering possible.
* `https://signup.target.com` — Cookie vulnerability detected. Parameter Name: `sessionID`. Reason: Missing `Secure` flag.

**🧾 Output Details Saved Silently (JSON Report)**
Full report includes:

* Timestamped findings history
* Request/response pairs
* Detected headers & cookies
* Exact matches of suspected XSS/SQLi injections

**Note:** Reports never overwrite — filenames are timestamped/incremented automatically.

---

## Example report structure

`sample_output.json` (example keys — actual structure may vary):

```json
{
  "scan_id": "2025-01-01T12-00-00Z-1234",
  "target": "https://signup.target.com",
  "scan_level": "medium",
  "findings": [
    {
      "type": "xss",
      "vector": "url_param",
      "evidence": "<script>alert(1)</script>",
      "parameter": "search",
      "severity": "critical",
      "timestamp": "2025-01-01T12:00:01Z"
    }
  ],
  "raw": {
    "requests": [ /* request/response pairs */ ]
  }
}
```

---

## Ethical & Legal

* Run this tool only against systems you own or have explicit permission to test.
* The author(s) are not responsible for misuse.

---

