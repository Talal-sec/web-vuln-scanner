# Web Vulnerability Scanner

A Python-based command-line web vulnerability scanner built as a graduation project. It crawls a target website and tests for common security vulnerabilities.

## Features

| Module | What it detects |
|--------|----------------|
| `sqli` | SQL Injection (error-based & boolean-based) |
| `xss` | Reflected Cross-Site Scripting |
| `headers` | Missing/weak security headers (CSP, HSTS, X-Frame-Options, etc.) |
| `open_redirect` | Open Redirect vulnerabilities |

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Scan with all modules
python main.py --url http://testphp.vulnweb.com

# Save findings to JSON
python main.py --url http://testphp.vulnweb.com --output results.json

# Run specific modules only
python main.py --url https://example.com --modules sqli xss

# Deeper crawl with verbose output
python main.py --url https://example.com --depth 3 --verbose
```

## Options

```
--url         Target URL (required)
--modules     Modules to run: sqli xss headers open_redirect (default: all)
--depth       Crawl depth (default: 2)
--timeout     Request timeout in seconds (default: 10)
--output      Save findings to a JSON file
--verbose     Print each scanned URL
```

## JSON Output Format

```json
{
  "target": "http://example.com",
  "scan_start": "2024-01-01T00:00:00Z",
  "scan_end": "2024-01-01T00:01:30Z",
  "total_findings": 3,
  "findings": [
    {
      "module": "sqli",
      "severity": "HIGH",
      "url": "http://example.com/search?q='",
      "parameter": "q",
      "evidence": "DB error pattern: 'you have an error in your sql syntax'",
      "description": "Possible SQL Injection in URL parameter 'q' — error-based"
    }
  ]
}
```

## Legal Disclaimer

This tool is for **authorized security testing and educational purposes only**. Only scan targets you own or have explicit written permission to test. Unauthorized scanning is illegal.

## Tech Stack

- Python 3.10+
- `requests` — HTTP client
- `beautifulsoup4` — HTML parsing / crawling
- `colorama` — colored terminal output
