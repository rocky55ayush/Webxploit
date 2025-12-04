# WebXploit – Advanced Web Vulnerability Scanner

WebXploit is a fast and powerful **Python-based web vulnerability scanner** that automatically detects:

- SQL Injection (Error, Boolean, Time-Based, UNION)
- Reflected XSS (context-aware, breakout attempts)
- CORS Misconfigurations
- Open Redirects
- Form-based vulnerabilities
- Optional **Selenium headless browser** verification for XSS

The scanner performs deep crawling, analyzes parameters & forms, and saves all findings into a structured JSON report.

---

## 🔥 Key Features
- Smart crawler (depth-based, avoids static files)
- SQLi detection using multiple techniques
- XSS detection with DOM/context analysis
- Open Redirect detector (Location, JS, Meta refresh)
- CORS misconfiguration scanner
- Multithreaded for faster scanning
- Wayback Machine URL integration
- Generates `urls.txt` + JSON report

---

## 🛠 Tech Stack
- Python 3  
- Libraries: `requests`, `beautifulsoup4`, `lxml`, `selenium` (optional), `webdriver-manager`

---

## 📥 Installation
git clone https://github.com/rocky55ayush/Webxploit.git
cd Webxploit
pip install -r requirements.txt

🚀 Usage
Basic Scan
python3 scanner.py -u https://target.com

Full Scan
python3 scanner.py -u https://target.com --depth 2 --threads 8 --verify-xss

⚙️ Main Arguments
Flag	Description
-u	Seed URL (required)
--depth	Crawl depth (default: 2)
--threads	Worker threads (default: 8)
--wayback	Fetch N Wayback URLs
--verify-xss	Enable Selenium XSS validation
--out	Output JSON file
📄 Output

urls.txt – all discovered URLs

scan_results.json – vulnerabilities, URLs, payloads, evidence

Example finding:

{
  "type": "sqli_error",
  "url": "https://target.com/search",
  "param": "q",
  "payload": "test'",
  "evidence": "you have an error in your sql syntax"
}

⚠️ Disclaimer

This tool is for educational and authorized security testing only.
Do NOT scan targets without permission.

Author
Ayush Yadav
Penetration Tester • Web Security Researcher

