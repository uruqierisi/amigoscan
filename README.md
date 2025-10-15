# AMIGOS-Pentest-Scanner-Ethical-Reconnaissance-Framework
A lightweight, modular OWASP-focused scanner supporting light/medium/deep scan intensity. Built for red team practitioners needing fast reconnaissance without excessive tool overhead.  🔐 For ethical use only — ensure authorized access prior to deployment.

⚙️ Features Overview
🔍 Scan Levels:

🟢 --light: Basic header checks, cookie parsing, CORS detection
🟡 --medium: Adds .env, .git, XSS payload injection checks
🔴 --deep: Full XSS/SQLi form tampering simulations, advanced leak tracing
🧾 Output Highlights:

Human-readable CLI summaries highlighting actionable findings
Full JSON artifacts preserved in background
Minimal UI noise – optimized for field usage
💻 Lightweight:

Asynchronous design (fast concurrent scanning)
Low runtime dependency footprint (Python only)
🧰 Installation Guide
On Debian/Kali Linux:

sudo apt update
sudo apt install python3 python3-pip git -y

pip3 install aiohttp termcolor
wget https://raw.githubusercontent.com/YOUR_USERNAME/pentest-scanner/main/pentest_scanner.py
chmod +x pentest_scanner.py

# Test it works:
./pentest_scanner.py --help
Alternatively,

git clone https://github.com/YOUR_USERNAME/pentest-scanner.git
cd pentest-scanner
pip install -r requirements.txt
Requires: Python ≥ 3.8

🚀 Usage Examples
✅ Quick Passive Check


./pentest_scanner.py example.com --light
🔄 Medium-Level Discovery + Payload Testing


./pentest_scanner.py https://signup.target.com --medium --output results/scans/target_signup.json
⚡ Deep Dive Into Forms / XSS Paths


./pentest_scanner.py --deep http://testphp.vulnweb.com/artists.php?artist=1
📂 List-Based Batch Scan
Create domains.txt:

https://app.example.com
http://shop.example.org/test?search=admin
...
Then run batch scan:


./pentest_scanner.py --file domains.txt --medium --output all-domains-report.json
🧪 Sample Output Summary



✅ SCAN REPORT SUMMARY
============================================================
🎯 Websites Scanned: 1
🔎 Total Issues Identified: 3

🔐 CRITICAL ISSUES DETECTED:
 [https://signup.target.com] ⚡️ XSS Triggered (2 parameters affected)
     Manually verify payload such as '<script>alert(1)</script>' in URL params.
 [https://signup.target.com] 🌐 Wildcard Origin With Credentials Allowed!

🟡 ACTIONABLE FINDINGS - VERIFY MANUALLY
 [https://signup.target.com] 200 → .git/
     Use wget/curl to download and inspect: https://signup.target.com/.git/
 [https://signup.target.com] 🔁 TRACE method allowed - HTTP verb tampering possible.
 [https://signup.target.com] ⚠ Cookie Vulnerability Detected
      Parameter Name: 'sessionID', Reason: Missing Secure
🧾 Output Details Saved Silently (JSON Report)
Full report includes:

Timestamped findings history
Request/response pairs
Detected headers & cookies
Exact matches of suspected XSS/SQLi injections
See example report structure:

sample_output.json [blocked]
Note: Reports never overwrite – incrementally appends timestamps automatically.
