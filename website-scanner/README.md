# SSL Certificate Scanner

A Python script that scans URLs and retrieves SSL certificate information including expiry dates. Outputs results to console and generates an HTML report.

## Features

- Scans multiple URLs from a configuration file
- Retrieves SSL certificate details:
  - Subject (Common Name)
  - Issuer
  - Valid from/until dates
  - Days remaining until expiry
  - Serial number
- Console output with formatted results
- HTML report with:
  - Summary cards (Valid/Expiring Soon/Error counts)
  - Detailed table with all certificates
  - Color-coded status indicators

## Setup

1. Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows
```
Use `deactivate` to exit from virtual environment.

2. Install dependencies (none required - uses standard library only):

```bash
pip install -r requirements.txt
```

3. Create your URLs file from the example:

```bash
cp urls.txt.example urls.txt
```

## Usage

1. Add URLs to `urls.txt` (one per line):

```
https://example.com
https://api.example.com
# Comments are ignored
```

2. Run the scanner:

```bash
python ssl_scanner.py
```

3. View results:
   - Console: Formatted output displayed immediately
   - HTML: Open `ssl_report.html` in a browser

## Output

### Console Output

```
================================================================================
SSL CERTIFICATE SCAN RESULTS
================================================================================
Scan Date: 2025-12-03 00:01:40
================================================================================

URL: https://www.example.com
------------------------------------------------------------
  Hostname:       www.example.com
  Subject:        www.example.com
  Issuer:         Amazon
  Valid From:     2025-10-20 00:00:00
  Valid Until:    2026-11-18 23:59:59
  Days Remaining: OK (351 days)
  Serial Number:  0C2E6A603CB2E3547CA257BC969D1815
```

### HTML Report

The HTML report includes:
- Summary cards showing counts of Valid, Expiring Soon, and Error/Expired certificates
- A table with all scanned URLs and their certificate details
- Color-coded status badges:
  - Green: Valid (> 30 days remaining)
  - Yellow: Expiring Soon (<= 30 days remaining)
  - Red: Expired or Error

## Configuration

Edit the constants at the top of `ssl_scanner.py` to customize:

```python
URLS_FILE = "urls.txt"      # Input file with URLs
HTML_OUTPUT = "ssl_report.html"  # Output HTML file
TIMEOUT = 10                # Connection timeout in seconds
```

## File Structure

```
website-scanner/
├── venv/               # Virtual environment (gitignored)
├── urls.txt            # Input: URLs to scan (gitignored)
├── urls.txt.example    # Example URLs file template
├── ssl_scanner.py      # Main scanner script
├── ssl_report.html     # Output: Generated HTML report (gitignored)
├── requirements.txt    # Python dependencies
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

## Requirements

- Python 3.10+
- No external dependencies (uses standard library only)
