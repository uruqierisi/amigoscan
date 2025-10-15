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

# Option A: Download single script (quick)
pip3 install aiohttp termcolor wget
wget https://raw.githubusercontent.com/YOUR_USERNAME/pentest-scanner/main/pentest_scanner.py
chmod +x pentest_scanner.py

# Option B: Clone repo (recommended for full project)
git clone https://github.com/YOUR_USERNAME/pentest-scanner.git
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
git clone https://github.com/YOUR_USERNAME/pentest-scanner.git
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

## GitHub Pages: `index.html` (terminal-style presentation)

Below is an `index.html` you can add to your repo and enable GitHub Pages for a styled terminal-like usage page.

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Pentest Scanner — Usage</title>
  <style>
    body { margin: 0; padding: 32px; background: #0b1220; color: #e6eef8; font-family: Arial, sans-serif; }
    .terminal { max-width: 900px; margin: 0 auto; background: linear-gradient(180deg,#07101a,#0d1724); border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.6); padding: 20px; color: #d6e6ff; font-family: Consolas, "Courier New", monospace; white-space: pre-wrap; line-height: 1.45; font-size: 15px; }
    .cmd { display: block; padding: 10px; background: rgba(0,0,0,0.12); border-radius: 6px; margin: 10px 0; }
    .hint { color: #99c0ff; font-size: 13px; margin-top: 6px; display:block; }
    .prompt { color:#7fe08a; margin-right:8px; }
  </style>
</head>
<body>
  <h1 style="text-align:center; color:#fff; font-family: Inter, Arial, sans-serif;">Pentest Scanner — Usage</h1>
  <div class="terminal">
    <span class="cmd"><span class="prompt">$</span>./pentest_scanner.py --help</span>

    <span class="cmd"><span class="prompt">$</span>git clone https://github.com/YOUR_USERNAME/pentest-scanner.git
cd pentest-scanner
pip install -r requirements.txt
<span class="hint"># Requires: Python ≥ 3.8</span></span>

    <span class="cmd"><span class="prompt">$</span>./pentest_scanner.py example.com --light
<span class="hint">🔄 Medium-Level Discovery + Payload Testing</span></span>

    <span class="cmd"><span class="prompt">$</span>./pentest_scanner.py https://signup.target.com --medium --output results/scans/target_signup.json
<span class="hint">⚡ Deep Dive Into Forms / XSS Paths</span></span>

    <span class="cmd"><span class="prompt">$</span>./pentest_scanner.py --deep "http://testphp.vulnweb.com/artists.php?artist=1"
<span class="hint">📂 List-Based Batch Scan</span></span>

    <span class="cmd"><span class="prompt">$</span># Create domains.txt with URLs (one per line), then run:
./pentest_scanner.py --file domains.txt --medium --output all-domains-report.json
<span class="hint">🧪 Sample Output Summary</span></span>
  </div>
</body>
</html>
```

---

## Next steps

* Replace `YOUR_USERNAME` with your GitHub username in the example clone URL.
* Add this README to the root of your repo (`README.md`) and/or add `index.html` for GitHub Pages.
* If you want, I can generate a `git diff` or a patch file you can apply directly — tell me the repo name/branch and I will prepare it.

Good luck — po e ke të kompletuar README + Pages të gatshme! 👌
