#!/usr/bin/env python3
"""
AWS IAM Group Scanner

Scans all IAM groups and their members across multiple AWS accounts,
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


def get_all_groups(iam_client) -> list:
    """Get all IAM groups with pagination."""
    groups = []
    paginator = iam_client.get_paginator("list_groups")

    for page in paginator.paginate():
        groups.extend(page["Groups"])

    return groups


def get_group_members(iam_client, group_name: str) -> list:
    """Get all users in a group."""
    try:
        paginator = iam_client.get_paginator("get_group")
        members = []
        for page in paginator.paginate(GroupName=group_name):
            members.extend(page.get("Users", []))
        return members
    except ClientError:
        return []


def get_group_policies(iam_client, group_name: str) -> dict:
    """Get all policies attached to a group (inline and managed)."""
    policies = {"inline": [], "managed": []}

    try:
        # Get inline policies
        paginator = iam_client.get_paginator("list_group_policies")
        for page in paginator.paginate(GroupName=group_name):
            policies["inline"].extend(page.get("PolicyNames", []))

        # Get managed policies
        paginator = iam_client.get_paginator("list_attached_group_policies")
        for page in paginator.paginate(GroupName=group_name):
            for policy in page.get("AttachedPolicies", []):
                policies["managed"].append(policy.get("PolicyName", ""))
    except ClientError:
        pass

    return policies


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


def scan_account(profile_name: str, account_name: str, verbose: bool = False) -> list:
    """Scan a single AWS account for IAM groups."""
    results = []

    try:
        session = boto3.Session(profile_name=profile_name)
        account_id = get_account_id(session)

        if not account_id:
            print(f"  Skipping {profile_name}: Unable to get account ID (credentials may be expired)")
            return []

        iam = session.client("iam")
        groups = get_all_groups(iam)

        if verbose:
            print(f"  Found {len(groups)} group(s)")

        for group in groups:
            group_name = group["GroupName"]
            group_id = group["GroupId"]
            group_arn = group["Arn"]
            group_create_date = group["CreateDate"]
            group_age_days = calculate_age_days(group_create_date)

            # Get group members
            members = get_group_members(iam, group_name)
            member_names = [m["UserName"] for m in members]
            member_count = len(members)

            # Get group policies
            policies = get_group_policies(iam, group_name)
            inline_policies = policies["inline"]
            managed_policies = policies["managed"]
            total_policies = len(inline_policies) + len(managed_policies)

            results.append({
                "AccountId": account_id,
                "AccountName": account_name,
                "GroupName": group_name,
                "GroupId": group_id,
                "GroupArn": group_arn,
                "CreateDate": format_datetime(group_create_date),
                "AgeDays": group_age_days,
                "MemberCount": member_count,
                "Members": ", ".join(member_names) if member_names else "N/A",
                "InlinePolicies": ", ".join(inline_policies) if inline_policies else "N/A",
                "InlinePolicyCount": len(inline_policies),
                "ManagedPolicies": ", ".join(managed_policies) if managed_policies else "N/A",
                "ManagedPolicyCount": len(managed_policies),
                "TotalPolicies": total_policies,
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
    print("IAM GROUP SCAN RESULTS")
    print(f"{'='*80}")

    for account_id, data in sorted(accounts.items()):
        rows = data["rows"]
        account_name = data["name"]
        total_members = sum(row["MemberCount"] for row in rows)

        print(f"\nAccount: {account_name} ({account_id})")
        print(f"  Groups: {len(rows)}")
        print(f"  Total Members: {total_members}")

        if verbose:
            for row in rows:
                print(f"\n    Group: {row['GroupName']}")
                print(f"      Members ({row['MemberCount']}): {row['Members']}")
                print(f"      Policies: {row['TotalPolicies']} (Inline: {row['InlinePolicyCount']}, Managed: {row['ManagedPolicyCount']})")
                if row['ManagedPolicies'] != 'N/A':
                    print(f"      Managed: {row['ManagedPolicies']}")


def write_csv(results: list, filepath: str):
    """Write results to CSV file."""
    if not results:
        print("No results to write to CSV.")
        return

    fieldnames = [
        "AccountId", "AccountName", "GroupName", "GroupId", "CreateDate", "AgeDays",
        "MemberCount", "Members", "TotalPolicies", "InlinePolicyCount", "ManagedPolicyCount",
        "InlinePolicies", "ManagedPolicies", "GroupArn"
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
    <title>AWS IAM Group Scan Report</title>
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
        .count-zero { color: #879596; }
        .count-high { color: #1d8102; font-weight: bold; }
        .timestamp { color: #879596; font-size: 12px; margin-bottom: 20px; }
        .result-count { color: #666; font-size: 13px; margin-top: 10px; }
        .members-cell { max-width: 300px; overflow: hidden; text-overflow: ellipsis; }
        .policies-cell { max-width: 250px; overflow: hidden; text-overflow: ellipsis; }
    </style>
</head>
<body>
    <h1>AWS IAM Group Scan Report</h1>
    <p class="timestamp">Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>

    <div class="summary">
        <strong>Summary:</strong>
        Groups: <span id="summaryGroups">0</span> |
        Accounts: <span id="summaryAccounts">0</span> |
        Total Members: <span id="summaryMembers">0</span> |
        Empty Groups: <span id="summaryEmpty">0</span>
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
            <label>Members</label>
            <select id="filterMembers">
                <option value="">All</option>
                <option value="empty">Empty (0 members)</option>
                <option value="has">Has members</option>
            </select>
        </div>
        <div class="filter-group">
            <label>Policies</label>
            <select id="filterPolicies">
                <option value="">All</option>
                <option value="none">No policies</option>
                <option value="has">Has policies</option>
            </select>
        </div>
        <div class="filter-group">
            <label>Group Age</label>
            <select id="filterAge">
                <option value="">All</option>
                <option value="90">Over 90 days</option>
                <option value="180">Over 180 days</option>
                <option value="365">Over 365 days</option>
            </select>
        </div>
        <button class="btn-clear" onclick="clearFilters()">Clear Filters</button>
    </div>

    <div class="result-count">Showing <span id="visibleCount">0</span> of <span id="totalCount">0</span> groups</div>

    <div class="table-container">
    <table id="dataTable">
        <thead>
            <tr>
                <th data-col="0">Account ID<span class="sort-icon"></span></th>
                <th data-col="1">Account Name<span class="sort-icon"></span></th>
                <th data-col="2">Group Name<span class="sort-icon"></span></th>
                <th data-col="3">Created<span class="sort-icon"></span></th>
                <th data-col="4">Age (Days)<span class="sort-icon"></span></th>
                <th data-col="5">Members<span class="sort-icon"></span></th>
                <th data-col="6">Member List<span class="sort-icon"></span></th>
                <th data-col="7">Policies<span class="sort-icon"></span></th>
                <th data-col="8">Managed Policies<span class="sort-icon"></span></th>
            </tr>
        </thead>
        <tbody>
"""

    for row in results:
        member_class = "count-zero" if row["MemberCount"] == 0 else ("count-high" if row["MemberCount"] >= 5 else "")
        policy_class = "count-zero" if row["TotalPolicies"] == 0 else ""

        html += f"""            <tr>
                <td>{row['AccountId']}</td>
                <td>{row['AccountName']}</td>
                <td>{row['GroupName']}</td>
                <td>{row['CreateDate']}</td>
                <td>{row['AgeDays']}</td>
                <td class="{member_class}">{row['MemberCount']}</td>
                <td class="members-cell" title="{row['Members']}">{row['Members']}</td>
                <td class="{policy_class}">{row['TotalPolicies']}</td>
                <td class="policies-cell" title="{row['ManagedPolicies']}">{row['ManagedPolicies']}</td>
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
const filterMembers = document.getElementById('filterMembers');
const filterPolicies = document.getElementById('filterPolicies');
const filterAge = document.getElementById('filterAge');

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

            // Numeric sort for count/days columns
            if ([4, 5, 7].includes(index)) {
                aVal = parseInt(aVal) || 0;
                bVal = parseInt(bVal) || 0;
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
    const members = filterMembers.value;
    const policies = filterPolicies.value;
    const age = filterAge.value;

    let visible = 0;
    const rows = tbody.querySelectorAll('tr');

    // Track stats for visible rows
    const visibleAccounts = new Set();
    let totalMembers = 0;
    let emptyGroups = 0;

    rows.forEach(row => {
        const cells = row.cells;
        const rowText = row.textContent.toLowerCase();
        const rowAccountId = cells[0].textContent;
        const rowAccountName = cells[1].textContent;
        const rowAge = parseInt(cells[4].textContent) || 0;
        const rowMemberCount = parseInt(cells[5].textContent) || 0;
        const rowPolicyCount = parseInt(cells[7].textContent) || 0;

        let show = true;

        if (search && !rowText.includes(search)) show = false;
        if (account && rowAccountName !== account) show = false;
        if (members === 'empty' && rowMemberCount > 0) show = false;
        if (members === 'has' && rowMemberCount === 0) show = false;
        if (policies === 'none' && rowPolicyCount > 0) show = false;
        if (policies === 'has' && rowPolicyCount === 0) show = false;
        if (age && rowAge < parseInt(age)) show = false;

        row.classList.toggle('hidden', !show);
        if (show) {
            visible++;
            visibleAccounts.add(rowAccountId);
            totalMembers += rowMemberCount;
            if (rowMemberCount === 0) emptyGroups++;
        }
    });

    document.getElementById('visibleCount').textContent = visible;
    document.getElementById('summaryGroups').textContent = visible;
    document.getElementById('summaryAccounts').textContent = visibleAccounts.size;
    document.getElementById('summaryMembers').textContent = totalMembers;
    document.getElementById('summaryEmpty').textContent = emptyGroups;
}

function clearFilters() {
    searchInput.value = '';
    filterAccount.value = '';
    filterMembers.value = '';
    filterPolicies.value = '';
    filterAge.value = '';
    applyFilters();
}

searchInput.addEventListener('input', applyFilters);
filterAccount.addEventListener('change', applyFilters);
filterMembers.addEventListener('change', applyFilters);
filterPolicies.addEventListener('change', applyFilters);
filterAge.addEventListener('change', applyFilters);

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
        description="Scan AWS IAM groups across multiple accounts"
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

        results = scan_account(profile, account_name, args.verbose)

        if results:
            all_results.extend(results)
            accounts_scanned += 1
        elif results == []:
            # Empty list could mean no groups or failed
            # Check if we got account_id to differentiate
            accounts_scanned += 1
        else:
            accounts_failed += 1

    # Summary
    summary = {
        "profiles_attempted": len(profiles),
        "accounts_scanned": accounts_scanned,
        "accounts_failed": accounts_failed,
        "total_groups": len(all_results),
        "total_members": sum(r["MemberCount"] for r in all_results),
        "empty_groups": len([r for r in all_results if r["MemberCount"] == 0]),
        "groups_without_policies": len([r for r in all_results if r["TotalPolicies"] == 0]),
    }

    # Print summary
    print(f"\n{'='*60}")
    print("SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Profiles attempted: {summary['profiles_attempted']}")
    print(f"Accounts scanned: {summary['accounts_scanned']}")
    print(f"Accounts failed: {summary['accounts_failed']}")
    print(f"Total groups: {summary['total_groups']}")
    print(f"Total members: {summary['total_members']}")
    print(f"Empty groups: {summary['empty_groups']}")
    print(f"Groups without policies: {summary['groups_without_policies']}")

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
