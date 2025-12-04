#!/usr/bin/env python3
"""
SSL Certificate Scanner
Scans URLs and retrieves SSL certificate information including expiry dates.
Outputs results to console and generates an HTML report.
"""

import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone
import os

# Configuration
URLS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "urls.txt")
HTML_OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssl_report.html")
TIMEOUT = 10


def get_ssl_certificate(hostname: str, port: int = 443) -> dict | None:
    """
    Retrieve SSL certificate information for a given hostname.

    Args:
        hostname: The hostname to connect to
        port: The port number (default: 443)

    Returns:
        Dictionary containing certificate info or None if failed
    """
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        print(f"  Error connecting to {hostname}:{port} - {e}")
        return None


def parse_cert_date(date_str: str) -> datetime:
    """Parse certificate date string to datetime object."""
    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")


def get_cert_info(url: str) -> dict:
    """
    Get certificate information for a URL.

    Args:
        url: The URL to scan

    Returns:
        Dictionary containing certificate details
    """
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path
    port = parsed.port or 443

    # Remove port from hostname if present
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    result = {
        "url": url,
        "hostname": hostname,
        "port": port,
        "status": "error",
        "issuer": None,
        "subject": None,
        "valid_from": None,
        "valid_until": None,
        "days_remaining": None,
        "serial_number": None,
        "error": None
    }

    cert = get_ssl_certificate(hostname, port)

    if cert is None:
        result["error"] = "Failed to retrieve certificate"
        return result

    try:
        # Parse issuer
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown"))

        # Parse subject
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        result["subject"] = subject_dict.get("commonName", "Unknown")

        # Parse dates
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")

        if not_before:
            result["valid_from"] = parse_cert_date(not_before)

        if not_after:
            result["valid_until"] = parse_cert_date(not_after)
            days_remaining = (result["valid_until"].replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
            result["days_remaining"] = days_remaining

        # Serial number
        result["serial_number"] = cert.get("serialNumber", "Unknown")

        result["status"] = "ok"

    except Exception as e:
        result["error"] = str(e)

    return result


def print_console_output(results: list[dict]) -> None:
    """Print results to console in a formatted way."""
    print("\n" + "=" * 80)
    print("SSL CERTIFICATE SCAN RESULTS")
    print("=" * 80)
    print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80 + "\n")

    for result in results:
        print(f"URL: {result['url']}")
        print("-" * 60)

        if result["status"] == "ok":
            print(f"  Hostname:       {result['hostname']}")
            print(f"  Subject:        {result['subject']}")
            print(f"  Issuer:         {result['issuer']}")
            print(f"  Valid From:     {result['valid_from'].strftime('%Y-%m-%d %H:%M:%S') if result['valid_from'] else 'N/A'}")
            print(f"  Valid Until:    {result['valid_until'].strftime('%Y-%m-%d %H:%M:%S') if result['valid_until'] else 'N/A'}")

            days = result["days_remaining"]
            if days is not None:
                if days < 0:
                    status_text = f"EXPIRED ({abs(days)} days ago)"
                elif days <= 30:
                    status_text = f"EXPIRING SOON ({days} days)"
                else:
                    status_text = f"OK ({days} days)"
                print(f"  Days Remaining: {status_text}")

            print(f"  Serial Number:  {result['serial_number']}")
        else:
            print(f"  Status:         ERROR")
            print(f"  Error:          {result['error']}")

        print()


def generate_html_report(results: list[dict], output_path: str) -> None:
    """Generate an HTML report from the scan results."""
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL Certificate Report</title>
    <style>
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: #f5f5f5;
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1 {{
            text-align: center;
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        .scan-date {{
            text-align: center;
            color: #7f8c8d;
            margin-bottom: 30px;
        }}
        .summary {{
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }}
        .summary-card {{
            background: white;
            padding: 20px 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card .number {{
            font-size: 2em;
            font-weight: bold;
        }}
        .summary-card .label {{
            color: #7f8c8d;
            margin-top: 5px;
        }}
        .summary-card.ok .number {{ color: #27ae60; }}
        .summary-card.warning .number {{ color: #f39c12; }}
        .summary-card.error .number {{ color: #e74c3c; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }}
        th {{
            background-color: #2c3e50;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        .status {{
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            display: inline-block;
        }}
        .status.ok {{
            background-color: #d4edda;
            color: #155724;
        }}
        .status.warning {{
            background-color: #fff3cd;
            color: #856404;
        }}
        .status.expired {{
            background-color: #f8d7da;
            color: #721c24;
        }}
        .status.error {{
            background-color: #f8d7da;
            color: #721c24;
        }}
        .url {{
            word-break: break-all;
            max-width: 300px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>SSL Certificate Report</h1>
        <p class="scan-date">Scan Date: {scan_date}</p>
"""

    # Calculate summary stats
    ok_count = sum(1 for r in results if r["status"] == "ok" and r["days_remaining"] and r["days_remaining"] > 30)
    warning_count = sum(1 for r in results if r["status"] == "ok" and r["days_remaining"] and 0 < r["days_remaining"] <= 30)
    error_count = sum(1 for r in results if r["status"] == "error" or (r["days_remaining"] is not None and r["days_remaining"] <= 0))

    html_content += f"""
        <div class="summary">
            <div class="summary-card ok">
                <div class="number">{ok_count}</div>
                <div class="label">Valid</div>
            </div>
            <div class="summary-card warning">
                <div class="number">{warning_count}</div>
                <div class="label">Expiring Soon</div>
            </div>
            <div class="summary-card error">
                <div class="number">{error_count}</div>
                <div class="label">Expired/Error</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Subject</th>
                    <th>Issuer</th>
                    <th>Valid Until</th>
                    <th>Days Remaining</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
"""

    for result in results:
        if result["status"] == "ok":
            days = result["days_remaining"]
            valid_until = result["valid_until"].strftime("%Y-%m-%d") if result["valid_until"] else "N/A"

            if days is None:
                status_class = "error"
                status_text = "Unknown"
                days_text = "N/A"
            elif days < 0:
                status_class = "expired"
                status_text = "Expired"
                days_text = f"{days}"
            elif days <= 30:
                status_class = "warning"
                status_text = "Expiring Soon"
                days_text = str(days)
            else:
                status_class = "ok"
                status_text = "Valid"
                days_text = str(days)

            html_content += f"""
                <tr>
                    <td class="url">{result['url']}</td>
                    <td>{result['subject'] or 'N/A'}</td>
                    <td>{result['issuer'] or 'N/A'}</td>
                    <td>{valid_until}</td>
                    <td>{days_text}</td>
                    <td><span class="status {status_class}">{status_text}</span></td>
                </tr>
"""
        else:
            html_content += f"""
                <tr>
                    <td class="url">{result['url']}</td>
                    <td colspan="4">{result['error'] or 'Connection failed'}</td>
                    <td><span class="status error">Error</span></td>
                </tr>
"""

    html_content += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""

    with open(output_path, "w") as f:
        f.write(html_content)

    print(f"HTML report generated: {output_path}")


def load_urls(file_path: str) -> list[str]:
    """Load URLs from a file, one per line."""
    urls = []

    if not os.path.exists(file_path):
        print(f"Error: URLs file not found: {file_path}")
        return urls

    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)

    return urls


def main():
    """Main function to run the SSL certificate scanner."""
    print("Loading URLs from:", URLS_FILE)
    urls = load_urls(URLS_FILE)

    if not urls:
        print("No URLs found to scan.")
        return

    print(f"Found {len(urls)} URL(s) to scan.\n")

    results = []
    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] Scanning: {url}")
        result = get_cert_info(url)
        results.append(result)

    # Output to console
    print_console_output(results)

    # Generate HTML report
    generate_html_report(results, HTML_OUTPUT)


if __name__ == "__main__":
    main()
