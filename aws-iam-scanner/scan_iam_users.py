#!/usr/bin/env python3
"""
AWS IAM User Scanner

Scans all IAM users and their access keys across multiple AWS accounts,
iterating through AWS profiles.
"""

import os
import sys
import csv
import json
import argparse
import configparser
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, ProfileNotFound, NoCredentialsError, TokenRetrievalError, SSOTokenLoadError


def get_aws_profiles(pattern: str = ".admin") -> dict:
    """Get all AWS profiles matching the pattern from ~/.aws/config.

    Returns a dict mapping profile_name -> account_name.
    """
    config_path = Path.home() / ".aws" / "config"

    if not config_path.exists():
        print(f"Error: AWS config file not found at {config_path}")
        return {}

    config = configparser.ConfigParser()
    config.read(config_path)

    profiles = {}
    for section in config.sections():
        if section.startswith("profile "):
            profile_name = section.replace("profile ", "")
            if pattern in profile_name:
                # Get account name from sso_account_name if available
                account_name = config.get(section, "sso_account_name", fallback=profile_name)
                profiles[profile_name] = account_name

    return dict(sorted(profiles.items()))


def get_account_id(session: boto3.Session) -> Optional[str]:
    """Get AWS Account ID using STS."""
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        return identity["Account"]
    except (ClientError, NoCredentialsError, TokenRetrievalError, SSOTokenLoadError) as e:
        return None
    except Exception as e:
        # Catch any other credential-related errors
        if "token" in str(e).lower() or "credential" in str(e).lower() or "sso" in str(e).lower():
            return None
        raise


def get_all_users(iam_client) -> list:
    """Get all IAM users with pagination."""
    users = []
    paginator = iam_client.get_paginator("list_users")

    for page in paginator.paginate():
        users.extend(page["Users"])

    return users


def has_console_access(iam_client, username: str) -> bool:
    """Check if user has console access (login profile)."""
    try:
        iam_client.get_login_profile(UserName=username)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise


def get_access_keys(iam_client, username: str) -> list:
    """Get all access keys for a user."""
    try:
        response = iam_client.list_access_keys(UserName=username)
        return response.get("AccessKeyMetadata", [])
    except ClientError:
        return []


def get_access_key_last_used(iam_client, access_key_id: str) -> dict:
    """Get last used information for an access key."""
    try:
        response = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
        return response.get("AccessKeyLastUsed", {})
    except ClientError:
        return {}


def calculate_age_days(create_date: datetime) -> int:
    """Calculate the age in days from creation date."""
    if create_date.tzinfo is None:
        create_date = create_date.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return (now - create_date).days


def format_datetime(dt) -> str:
    """Format datetime object to ISO string."""
    if dt is None:
        return "N/A"
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return str(dt)


def calculate_last_used_days(last_used_date) -> str:
    """Calculate days since last used."""
    if last_used_date is None:
        return "N/A"
    if last_used_date.tzinfo is None:
        last_used_date = last_used_date.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return str((now - last_used_date).days)


def scan_account(profile_name: str, account_name: str, verbose: bool = False, exclude_bedrock: bool = False) -> list:
    """Scan a single AWS account for IAM users and their keys."""
    results = []

    try:
        session = boto3.Session(profile_name=profile_name)
        account_id = get_account_id(session)

        if not account_id:
            print(f"  Skipping {profile_name}: Unable to get account ID (credentials may be expired)")
            return []

        iam = session.client("iam")
        users = get_all_users(iam)

        # Filter out BedrockAPIKey users if requested
        if exclude_bedrock:
            users = [u for u in users if not u["UserName"].startswith("BedrockAPIKey-")]

        if verbose:
            print(f"  Found {len(users)} user(s)")

        for user in users:
            username = user["UserName"]
            user_id = user["UserId"]
            user_create_date = user["CreateDate"]
            user_create_days = calculate_age_days(user_create_date)
            password_last_used = user.get("PasswordLastUsed")

            # Check console access
            console_access = has_console_access(iam, username)

            # Get access keys
            access_keys = get_access_keys(iam, username)

            if access_keys:
                # Create a row for each access key
                for key in access_keys:
                    key_id = key["AccessKeyId"]
                    key_status = key["Status"]
                    key_create_date = key["CreateDate"]
                    key_age_days = calculate_age_days(key_create_date)

                    # Get last used info
                    last_used_info = get_access_key_last_used(iam, key_id)
                    last_used_date = last_used_info.get("LastUsedDate")
                    last_used_service = last_used_info.get("ServiceName", "N/A")
                    last_used_days = calculate_last_used_days(last_used_date)

                    results.append({
                        "AccountId": account_id,
                        "AccountName": account_name,
                        "Username": username,
                        "ConsoleAccess": "TRUE" if console_access else "FALSE",
                        "AccessKeyId": key_id,
                        "Status": key_status,
                        "CreateDate": format_datetime(key_create_date),
                        "LastUsedDate": format_datetime(last_used_date),
                        "LastUsedDays": last_used_days,
                        "LastUsedService": last_used_service,
                        "AgeDays": key_age_days,
                        "PasswordLastUsed": format_datetime(password_last_used),
                        "UserId": user_id,
                        "UserCreateDate": format_datetime(user_create_date),
                        "UserCreateDays": user_create_days,
                    })
            else:
                # User has no access keys - still include them
                results.append({
                    "AccountId": account_id,
                    "AccountName": account_name,
                    "Username": username,
                    "ConsoleAccess": "TRUE" if console_access else "FALSE",
                    "AccessKeyId": "N/A",
                    "Status": "N/A",
                    "CreateDate": "N/A",
                    "LastUsedDate": "N/A",
                    "LastUsedDays": "N/A",
                    "LastUsedService": "N/A",
                    "AgeDays": "N/A",
                    "PasswordLastUsed": format_datetime(password_last_used),
                    "UserId": user_id,
                    "UserCreateDate": format_datetime(user_create_date),
                    "UserCreateDays": user_create_days,
                })

        return results

    except ProfileNotFound:
        print(f"  Skipping {profile_name}: Profile not found")
        return []
    except (NoCredentialsError, TokenRetrievalError, SSOTokenLoadError):
        print(f"  Skipping {profile_name}: Credentials expired or unavailable (run 'aws sso login')")
        return []
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "AccessDenied":
            print(f"  Skipping {profile_name}: Access denied to IAM")
        else:
            print(f"  Skipping {profile_name}: {e}")
        return []
    except Exception as e:
        # Catch any other credential-related errors
        if "token" in str(e).lower() or "credential" in str(e).lower() or "sso" in str(e).lower():
            print(f"  Skipping {profile_name}: SSO/Credential error (run 'aws sso login')")
            return []
        print(f"  Skipping {profile_name}: Unexpected error - {e}")
        return []


def print_report(results: list, verbose: bool = False):
    """Print results to console in a formatted way."""
    if not results:
        print("\nNo results to display.")
        return

    # Group by account
    accounts = {}
    for row in results:
        account_id = row["AccountId"]
        if account_id not in accounts:
            accounts[account_id] = {"name": row["AccountName"], "rows": []}
        accounts[account_id]["rows"].append(row)

    print(f"\n{'='*80}")
    print("IAM USER SCAN RESULTS")
    print(f"{'='*80}")

    for account_id, data in sorted(accounts.items()):
        rows = data["rows"]
        account_name = data["name"]
        # Get unique users
        users = set(row["Username"] for row in rows)
        keys_with_access = [row for row in rows if row["AccessKeyId"] != "N/A"]
        active_keys = [row for row in keys_with_access if row["Status"] == "Active"]

        print(f"\nAccount: {account_name} ({account_id})")
        print(f"  Users: {len(users)}")
        print(f"  Access Keys: {len(keys_with_access)} (Active: {len(active_keys)})")

        if verbose:
            for row in rows:
                status_color = "\033[92m" if row["Status"] == "Active" else "\033[91m"
                reset = "\033[0m"
                console = "\033[92mYes\033[0m" if row["ConsoleAccess"] == "TRUE" else "\033[90mNo\033[0m"

                print(f"\n    User: {row['Username']}")
                print(f"      Console Access: {console}")
                if row["AccessKeyId"] != "N/A":
                    print(f"      Key: {row['AccessKeyId']} | {status_color}{row['Status']}{reset} | Age: {row['AgeDays']} days")
                    print(f"      Last Used: {row['LastUsedDate']} ({row['LastUsedDays']} days ago) - {row['LastUsedService']}")


def write_csv(results: list, filepath: str):
    """Write results to CSV file."""
    if not results:
        print("No results to write to CSV.")
        return

    fieldnames = [
        "AccountId", "AccountName", "Username", "ConsoleAccess", "AccessKeyId", "Status",
        "CreateDate", "AgeDays", "LastUsedDate", "LastUsedDays", "LastUsedService",
        "UserCreateDate", "UserCreateDays", "PasswordLastUsed", "UserId"
    ]

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nCSV report saved to: {filepath}")


def write_html(results: list, filepath: str):
    """Write results to HTML file with sorting and filtering."""
    if not results:
        print("No results to write to HTML.")
        return

    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS IAM User Scan Report</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            color: #232f3e;
            border-bottom: 3px solid #ff9900;
            padding-bottom: 10px;
        }
        .summary {
            background-color: #fff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .filters {
            background-color: #fff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: center;
        }
        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }
        .filter-group label {
            font-size: 11px;
            font-weight: bold;
            color: #666;
        }
        .filter-group input, .filter-group select {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 13px;
        }
        .filter-group input { width: 180px; }
        .filter-group select { min-width: 120px; }
        .btn-clear {
            padding: 8px 16px;
            background-color: #232f3e;
            color: #fff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            margin-top: 18px;
        }
        .btn-clear:hover { background-color: #37475a; }
        .table-container {
            overflow-x: auto;
            background-color: #fff;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-radius: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            white-space: nowrap;
        }
        th {
            background-color: #232f3e;
            color: #fff;
            padding: 12px 8px;
            text-align: left;
            font-size: 12px;
            cursor: pointer;
            user-select: none;
            position: sticky;
            top: 0;
        }
        th:hover { background-color: #37475a; }
        th .sort-icon { margin-left: 5px; opacity: 0.5; }
        th.sort-asc .sort-icon::after { content: ' ▲'; opacity: 1; }
        th.sort-desc .sort-icon::after { content: ' ▼'; opacity: 1; }
        td {
            padding: 10px 8px;
            border-bottom: 1px solid #ddd;
            font-size: 12px;
        }
        tr:hover { background-color: #f9f9f9; }
        tr.hidden { display: none; }
        .status-active { color: #1d8102; font-weight: bold; }
        .status-inactive { color: #d13212; font-weight: bold; }
        .status-na { color: #879596; }
        .console-yes { color: #1d8102; }
        .console-no { color: #879596; }
        .age-warning { color: #ff9900; font-weight: bold; }
        .age-danger { color: #d13212; font-weight: bold; }
        .timestamp { color: #879596; font-size: 12px; margin-bottom: 20px; }
        .result-count { color: #666; font-size: 13px; margin-top: 10px; }
    </style>
</head>
<body>
    <h1>AWS IAM User Scan Report</h1>
    <p class="timestamp">Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>

    <div class="summary">
        <strong>Summary:</strong>
        Records: <span id="summaryRecords">0</span> |
        Accounts: <span id="summaryAccounts">0</span> |
        Users: <span id="summaryUsers">0</span> |
        Active Keys: <span id="summaryActiveKeys">0</span>
    </div>

    <div class="filters">
        <div class="filter-group">
            <label>Search</label>
            <input type="text" id="searchInput" placeholder="Search all columns...">
        </div>
        <div class="filter-group">
            <label>Account</label>
            <select id="filterAccount"><option value="">All Accounts</option></select>
        </div>
        <div class="filter-group">
            <label>Console Access</label>
            <select id="filterConsole">
                <option value="">All</option>
                <option value="Yes">Yes</option>
                <option value="No">No</option>
            </select>
        </div>
        <div class="filter-group">
            <label>Key Status</label>
            <select id="filterStatus">
                <option value="">All</option>
                <option value="Active">Active</option>
                <option value="Inactive">Inactive</option>
                <option value="N/A">No Key</option>
            </select>
        </div>
        <div class="filter-group">
            <label>Key Age</label>
            <select id="filterAge">
                <option value="">All</option>
                <option value="90">Over 90 days</option>
                <option value="180">Over 180 days</option>
                <option value="365">Over 365 days</option>
            </select>
        </div>
        <div class="filter-group">
            <label>Last Used</label>
            <select id="filterLastUsed">
                <option value="">All</option>
                <option value="30">Over 30 days</option>
                <option value="90">Over 90 days</option>
                <option value="180">Over 180 days</option>
                <option value="365">Over 365 days</option>
            </select>
        </div>
        <button class="btn-clear" onclick="clearFilters()">Clear Filters</button>
    </div>

    <div class="result-count">Showing <span id="visibleCount">0</span> of <span id="totalCount">0</span> records</div>

    <div class="table-container">
    <table id="dataTable">
        <thead>
            <tr>
                <th data-col="0">Account ID<span class="sort-icon"></span></th>
                <th data-col="1">Account Name<span class="sort-icon"></span></th>
                <th data-col="2">Username<span class="sort-icon"></span></th>
                <th data-col="3">Console<span class="sort-icon"></span></th>
                <th data-col="4">Access Key ID<span class="sort-icon"></span></th>
                <th data-col="5">Status<span class="sort-icon"></span></th>
                <th data-col="6">Key Created<span class="sort-icon"></span></th>
                <th data-col="7">Key Age (Days)<span class="sort-icon"></span></th>
                <th data-col="8">Last Used<span class="sort-icon"></span></th>
                <th data-col="9">Last Used (Days)<span class="sort-icon"></span></th>
                <th data-col="10">Service<span class="sort-icon"></span></th>
                <th data-col="11">User Created<span class="sort-icon"></span></th>
                <th data-col="12">User Age (Days)<span class="sort-icon"></span></th>
            </tr>
        </thead>
        <tbody>
"""

    for row in results:
        status_class = "status-active" if row["Status"] == "Active" else ("status-inactive" if row["Status"] == "Inactive" else "status-na")
        console_class = "console-yes" if row["ConsoleAccess"] == "TRUE" else "console-no"
        console_text = "Yes" if row["ConsoleAccess"] == "TRUE" else "No"

        age_class = ""
        if row["AgeDays"] != "N/A":
            if int(row["AgeDays"]) > 365:
                age_class = "age-danger"
            elif int(row["AgeDays"]) > 180:
                age_class = "age-warning"

        last_used_class = ""
        if row["LastUsedDays"] != "N/A":
            if int(row["LastUsedDays"]) > 365:
                last_used_class = "age-danger"
            elif int(row["LastUsedDays"]) > 180:
                last_used_class = "age-warning"

        html += f"""            <tr>
                <td>{row['AccountId']}</td>
                <td>{row['AccountName']}</td>
                <td>{row['Username']}</td>
                <td class="{console_class}">{console_text}</td>
                <td>{row['AccessKeyId']}</td>
                <td class="{status_class}">{row['Status']}</td>
                <td>{row['CreateDate']}</td>
                <td class="{age_class}">{row['AgeDays']}</td>
                <td>{row['LastUsedDate']}</td>
                <td class="{last_used_class}">{row['LastUsedDays']}</td>
                <td>{row['LastUsedService']}</td>
                <td>{row['UserCreateDate']}</td>
                <td>{row['UserCreateDays']}</td>
            </tr>
"""

    html += """        </tbody>
    </table>
    </div>

<script>
const table = document.getElementById('dataTable');
const tbody = table.querySelector('tbody');
const headers = table.querySelectorAll('th');
const searchInput = document.getElementById('searchInput');
const filterAccount = document.getElementById('filterAccount');
const filterConsole = document.getElementById('filterConsole');
const filterStatus = document.getElementById('filterStatus');
const filterAge = document.getElementById('filterAge');
const filterLastUsed = document.getElementById('filterLastUsed');

// Populate account filter
const accounts = new Set();
tbody.querySelectorAll('tr').forEach(row => {
    const accountName = row.cells[1].textContent;
    accounts.add(accountName);
});
Array.from(accounts).sort().forEach(account => {
    const option = document.createElement('option');
    option.value = account;
    option.textContent = account;
    filterAccount.appendChild(option);
});

// Sorting
let sortCol = -1;
let sortAsc = true;

headers.forEach((header, index) => {
    header.addEventListener('click', () => {
        if (sortCol === index) {
            sortAsc = !sortAsc;
        } else {
            sortCol = index;
            sortAsc = true;
        }

        headers.forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
        header.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');

        const rows = Array.from(tbody.querySelectorAll('tr'));
        rows.sort((a, b) => {
            let aVal = a.cells[index].textContent;
            let bVal = b.cells[index].textContent;

            // Numeric sort for day columns
            if ([7, 9, 12].includes(index)) {
                aVal = aVal === 'N/A' ? -1 : parseInt(aVal);
                bVal = bVal === 'N/A' ? -1 : parseInt(bVal);
                return sortAsc ? aVal - bVal : bVal - aVal;
            }

            return sortAsc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
        });

        rows.forEach(row => tbody.appendChild(row));
    });
});

// Filtering
function applyFilters() {
    const search = searchInput.value.toLowerCase();
    const account = filterAccount.value;
    const console = filterConsole.value;
    const status = filterStatus.value;
    const age = filterAge.value;
    const lastUsed = filterLastUsed.value;

    let visible = 0;
    const rows = tbody.querySelectorAll('tr');

    // Track stats for visible rows
    const visibleAccounts = new Set();
    const visibleUsers = new Set();
    let activeKeys = 0;

    rows.forEach(row => {
        const cells = row.cells;
        const rowText = row.textContent.toLowerCase();
        const rowAccountId = cells[0].textContent;
        const rowAccountName = cells[1].textContent;
        const rowUsername = cells[2].textContent;
        const rowConsole = cells[3].textContent;
        const rowStatus = cells[5].textContent;
        const rowAge = cells[7].textContent;
        const rowLastUsedDays = cells[9].textContent;

        let show = true;

        if (search && !rowText.includes(search)) show = false;
        if (account && rowAccountName !== account) show = false;
        if (console && rowConsole !== console) show = false;
        if (status && rowStatus !== status) show = false;
        if (age && rowAge !== 'N/A' && parseInt(rowAge) < parseInt(age)) show = false;
        if (age && rowAge === 'N/A') show = false;
        if (lastUsed && rowLastUsedDays !== 'N/A' && parseInt(rowLastUsedDays) < parseInt(lastUsed)) show = false;
        if (lastUsed && rowLastUsedDays === 'N/A') show = false;

        row.classList.toggle('hidden', !show);
        if (show) {
            visible++;
            visibleAccounts.add(rowAccountId);
            visibleUsers.add(rowAccountId + '|' + rowUsername);
            if (rowStatus === 'Active') activeKeys++;
        }
    });

    document.getElementById('visibleCount').textContent = visible;
    document.getElementById('summaryRecords').textContent = visible;
    document.getElementById('summaryAccounts').textContent = visibleAccounts.size;
    document.getElementById('summaryUsers').textContent = visibleUsers.size;
    document.getElementById('summaryActiveKeys').textContent = activeKeys;
}

function clearFilters() {
    searchInput.value = '';
    filterAccount.value = '';
    filterConsole.value = '';
    filterStatus.value = '';
    filterAge.value = '';
    filterLastUsed.value = '';
    applyFilters();
}

searchInput.addEventListener('input', applyFilters);
filterAccount.addEventListener('change', applyFilters);
filterConsole.addEventListener('change', applyFilters);
filterStatus.addEventListener('change', applyFilters);
filterAge.addEventListener('change', applyFilters);
filterLastUsed.addEventListener('change', applyFilters);

// Initial count
document.getElementById('totalCount').textContent = tbody.querySelectorAll('tr').length;
applyFilters();
</script>
</body>
</html>
"""

    with open(filepath, "w") as f:
        f.write(html)

    print(f"\nHTML report saved to: {filepath}")


def write_json(results: list, filepath: str, summary: dict):
    """Write results to JSON file."""
    output_data = {
        "timestamp": datetime.now().isoformat(),
        "summary": summary,
        "results": results,
    }

    with open(filepath, "w") as f:
        json.dump(output_data, f, indent=2, default=str)

    print(f"\nJSON report saved to: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="Scan AWS IAM users and access keys across multiple accounts"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output results to JSON file"
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="Output results to CSV file"
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Output results to HTML file"
    )
    parser.add_argument(
        "--profile",
        help="Scan only a specific AWS profile"
    )
    parser.add_argument(
        "--profile-pattern",
        default=".admin",
        help="Pattern to match AWS profiles (default: .admin)"
    )
    parser.add_argument(
        "--exclude-bedrock",
        action="store_true",
        help="Exclude users starting with 'BedrockAPIKey-'"
    )

    args = parser.parse_args()

    # Get profiles to scan
    if args.profile:
        # For single profile, try to get account name from config
        all_profiles = get_aws_profiles("")  # Get all profiles to find account name
        account_name = all_profiles.get(args.profile, args.profile)
        profiles = {args.profile: account_name}
    else:
        profiles = get_aws_profiles(args.profile_pattern)

    if not profiles:
        print(f"No AWS profiles found matching pattern '{args.profile_pattern}'")
        sys.exit(1)

    print(f"Found {len(profiles)} profile(s) to scan")
    print(f"{'='*60}")

    all_results = []
    accounts_scanned = 0
    accounts_failed = 0

    for i, (profile, account_name) in enumerate(profiles.items(), 1):
        print(f"[{i}/{len(profiles)}] Scanning profile: {profile} ({account_name})")

        results = scan_account(profile, account_name, args.verbose, args.exclude_bedrock)

        if results:
            all_results.extend(results)
            accounts_scanned += 1
        else:
            accounts_failed += 1

    # Summary
    summary = {
        "profiles_attempted": len(profiles),
        "accounts_scanned": accounts_scanned,
        "accounts_failed": accounts_failed,
        "total_records": len(all_results),
        "unique_users": len(set((r["AccountId"], r["Username"]) for r in all_results)),
        "total_keys": len([r for r in all_results if r["AccessKeyId"] != "N/A"]),
        "active_keys": len([r for r in all_results if r["Status"] == "Active"]),
    }

    # Print summary
    print(f"\n{'='*60}")
    print("SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Profiles attempted: {summary['profiles_attempted']}")
    print(f"Accounts scanned: {summary['accounts_scanned']}")
    print(f"Accounts failed: {summary['accounts_failed']}")
    print(f"Total records: {summary['total_records']}")
    print(f"Unique users: {summary['unique_users']}")
    print(f"Total access keys: {summary['total_keys']}")
    print(f"Active access keys: {summary['active_keys']}")

    # Print detailed report if verbose
    if args.verbose:
        print_report(all_results, args.verbose)

    # Output files
    if args.csv:
        write_csv(all_results, args.csv)

    if args.html:
        write_html(all_results, args.html)

    if args.output:
        write_json(all_results, args.output, summary)


if __name__ == "__main__":
    main()
