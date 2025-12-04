#!/usr/bin/env python3
"""
Entra ID Group Scanner

Lists users in a Microsoft Entra ID group and checks their account status.
"""

import os
import sys
import json
import argparse
from datetime import datetime

import msal
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Microsoft Graph API endpoint
GRAPH_API_ENDPOINT = "https://graph.microsoft.com/v1.0"


def get_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Acquire access token using client credentials flow."""
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    scope = ["https://graph.microsoft.com/.default"]

    app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret,
    )

    result = app.acquire_token_for_client(scopes=scope)

    if "access_token" in result:
        return result["access_token"]
    else:
        error = result.get("error_description", result.get("error", "Unknown error"))
        raise Exception(f"Failed to acquire token: {error}")


def search_group_by_name(access_token: str, group_name: str) -> list:
    """Search for groups by display name."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    url = f"{GRAPH_API_ENDPOINT}/groups"
    params = {
        "$filter": f"displayName eq '{group_name}'",
        "$select": "id,displayName,description,membershipRule",
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        return response.json().get("value", [])
    else:
        raise Exception(f"Failed to search groups: {response.status_code} - {response.text}")


def get_group_by_id(access_token: str, group_id: str) -> dict:
    """Get group details by ID."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    url = f"{GRAPH_API_ENDPOINT}/groups/{group_id}"
    params = {
        "$select": "id,displayName,description,membershipRule",
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return None
    else:
        raise Exception(f"Failed to get group: {response.status_code} - {response.text}")


def get_group_members(access_token: str, group_id: str) -> list:
    """Get all members of a group (handles pagination)."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    members = []
    url = f"{GRAPH_API_ENDPOINT}/groups/{group_id}/members"
    params = {
        "$select": "id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,lastPasswordChangeDateTime,signInActivity",
        "$top": 100,
    }

    while url:
        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json()
            members.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            params = {}  # nextLink includes params
        else:
            raise Exception(f"Failed to get group members: {response.status_code} - {response.text}")

    return members


def get_group_membership_audit(access_token: str, group_id: str) -> dict:
    """Get audit logs for when users were added to the group. Returns dict of user_id -> added_date."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    membership_dates = {}
    url = f"{GRAPH_API_ENDPOINT}/auditLogs/directoryAudits"
    params = {
        "$filter": f"activityDisplayName eq 'Add member to group' and targetResources/any(t: t/id eq '{group_id}')",
        "$orderby": "activityDateTime desc",
        "$top": 100,
    }

    try:
        while url:
            response = requests.get(url, headers=headers, params=params)

            if response.status_code == 200:
                data = response.json()
                for audit in data.get("value", []):
                    activity_date = audit.get("activityDateTime", "N/A")
                    # Find the user that was added
                    for target in audit.get("targetResources", []):
                        if target.get("@odata.type") == "#microsoft.graph.targetResource":
                            # Check modified properties for the added user
                            for prop in target.get("modifiedProperties", []):
                                if prop.get("displayName") == "Group.ObjectID":
                                    continue
                                # The user ID is in the target resources
                        if target.get("type") == "User":
                            user_id = target.get("id")
                            if user_id and user_id not in membership_dates:
                                membership_dates[user_id] = activity_date

                url = data.get("@odata.nextLink")
                params = {}
            elif response.status_code == 403:
                # No permission for audit logs
                return None
            else:
                return None
    except Exception:
        return None

    return membership_dates


def format_user_status(member: dict, membership_dates: dict = None) -> dict:
    """Format member data into user status dict."""
    # Only process user objects (skip groups, service principals, etc.)
    odata_type = member.get("@odata.type", "")
    if odata_type and "user" not in odata_type.lower():
        return None

    user_id = member.get("id", "N/A")
    added_to_group = "N/A"
    if membership_dates and user_id in membership_dates:
        added_to_group = membership_dates[user_id]

    return {
        "id": user_id,
        "display_name": member.get("displayName", "N/A"),
        "email": member.get("userPrincipalName", member.get("mail", "N/A")),
        "mail": member.get("mail", "N/A"),
        "account_enabled": member.get("accountEnabled", "N/A"),
        "created_date": member.get("createdDateTime", "N/A"),
        "last_password_change": member.get("lastPasswordChangeDateTime", "N/A"),
        "last_sign_in": member.get("signInActivity", {}).get("lastSignInDateTime", "N/A") if member.get("signInActivity") else "N/A",
        "last_non_interactive_sign_in": member.get("signInActivity", {}).get("lastNonInteractiveSignInDateTime", "N/A") if member.get("signInActivity") else "N/A",
        "added_to_group": added_to_group,
    }


def load_emails_from_file(filepath: str) -> set:
    """Load email addresses from a file (one per line)."""
    emails = set()
    with open(filepath, "r") as f:
        for line in f:
            email = line.strip().lower()
            if email and not email.startswith("#"):
                emails.add(email)
    return emails


def print_user_status(user: dict, verbose: bool = False, show_added_date: bool = False):
    """Print user status in a formatted way."""
    status = "ENABLED" if user["account_enabled"] is True else "DISABLED" if user["account_enabled"] is False else "UNKNOWN"

    if user["account_enabled"] is True:
        status_color = "\033[92m"  # Green
    elif user["account_enabled"] is False:
        status_color = "\033[91m"  # Red
    else:
        status_color = "\033[93m"  # Yellow
    reset_color = "\033[0m"

    print(f"\n{'='*60}")
    print(f"Display Name: {user['display_name']}")
    print(f"Email: {user['email']}")
    print(f"Status: {status_color}{status}{reset_color}")
    if show_added_date and user.get('added_to_group') != 'N/A':
        print(f"Added to Group: {user['added_to_group']}")

    if verbose:
        print(f"User ID: {user['id']}")
        print(f"Mail: {user['mail']}")
        print(f"Created: {user['created_date']}")
        print(f"Last Password Change: {user['last_password_change']}")
        print(f"Last Sign-In: {user['last_sign_in']}")
        print(f"Last Non-Interactive Sign-In: {user['last_non_interactive_sign_in']}")
        if user.get('added_to_group'):
            print(f"Added to Group: {user['added_to_group']}")


def main():
    parser = argparse.ArgumentParser(
        description="List users in an Entra ID group and check their account status"
    )
    group_input = parser.add_mutually_exclusive_group(required=True)
    group_input.add_argument(
        "-n", "--name",
        help="Group display name to search for"
    )
    group_input.add_argument(
        "-i", "--id",
        help="Group ID (GUID)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed user information"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output results to JSON file"
    )
    parser.add_argument(
        "-c", "--compare",
        help="Compare group members with a list of emails from a file"
    )
    parser.add_argument(
        "-a", "--added-date",
        action="store_true",
        help="Show when users were added to the group (requires AuditLog.Read.All permission)"
    )

    args = parser.parse_args()

    # Get credentials from environment variables
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")

    if not all([tenant_id, client_id, client_secret]):
        print("Error: Missing required environment variables.")
        print("Please set the following in your .env file:")
        print("  - AZURE_TENANT_ID")
        print("  - AZURE_CLIENT_ID")
        print("  - AZURE_CLIENT_SECRET")
        sys.exit(1)

    try:
        access_token = get_access_token(tenant_id, client_id, client_secret)
    except Exception as e:
        print(f"Authentication failed: {e}")
        sys.exit(1)

    # Find the group
    group = None
    if args.id:
        print(f"Looking up group by ID: {args.id}")
        group = get_group_by_id(access_token, args.id)
        if not group:
            print(f"Error: Group with ID '{args.id}' not found.")
            sys.exit(1)
    else:
        print(f"Searching for group: {args.name}")
        groups = search_group_by_name(access_token, args.name)
        if not groups:
            print(f"Error: No group found with name '{args.name}'")
            sys.exit(1)
        elif len(groups) > 1:
            print(f"Warning: Multiple groups found with name '{args.name}':")
            for g in groups:
                print(f"  - {g['displayName']} (ID: {g['id']})")
            print("Using the first match. Use --id for a specific group.")
        group = groups[0]

    print(f"\n{'='*60}")
    print(f"GROUP: {group['displayName']}")
    print(f"ID: {group['id']}")
    if group.get('description'):
        print(f"Description: {group['description']}")
    print(f"{'='*60}")

    # Get group members
    print("\nFetching group members...")
    members = get_group_members(access_token, group['id'])

    # Get membership audit data if requested
    membership_dates = None
    if args.added_date:
        print("Fetching membership audit logs...")
        membership_dates = get_group_membership_audit(access_token, group['id'])
        if membership_dates is None:
            print("Warning: Could not fetch audit logs. Make sure you have AuditLog.Read.All permission.")
            print("Note: Audit logs are only available for 30 days (or longer with Entra ID P1/P2).")

    # Filter and format user members only
    users = []
    for member in members:
        user = format_user_status(member, membership_dates)
        if user:
            users.append(user)

    if not users:
        print("No user members found in this group.")
        sys.exit(0)

    print(f"Found {len(users)} user(s) in the group.")

    summary = {"total": len(users), "enabled": 0, "disabled": 0, "unknown": 0}
    disabled_users = []

    for user in users:
        print_user_status(user, args.verbose, args.added_date)

        if user["account_enabled"] is True:
            summary["enabled"] += 1
        elif user["account_enabled"] is False:
            summary["disabled"] += 1
            disabled_users.append(user)
        else:
            summary["unknown"] += 1

    # Print summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"Group: {group['displayName']}")
    print(f"Total users: {summary['total']}")
    print(f"  - Enabled: {summary['enabled']}")
    print(f"  - Disabled: {summary['disabled']}")
    if summary['unknown'] > 0:
        print(f"  - Unknown: {summary['unknown']}")

    if disabled_users:
        print(f"\n\033[91mDISABLED USERS:\033[0m")
        for user in disabled_users:
            print(f"  - {user['display_name']} ({user['email']})")

    # Compare with file if requested
    comparison_results = None
    if args.compare:
        if not os.path.exists(args.compare):
            print(f"\nWarning: Comparison file '{args.compare}' not found. Skipping comparison.")
        else:
            file_emails = load_emails_from_file(args.compare)
            group_emails = {user['email'].lower() for user in users}
            group_mail_attrs = {user['mail'].lower() for user in users if user['mail'] != 'N/A'}
            all_group_emails = group_emails | group_mail_attrs

            # Users in group but not in file
            in_group_not_in_file = []
            for user in users:
                user_emails = {user['email'].lower()}
                if user['mail'] != 'N/A':
                    user_emails.add(user['mail'].lower())
                if not user_emails & file_emails:
                    in_group_not_in_file.append(user)

            # Users in file but not in group
            in_file_not_in_group = file_emails - all_group_emails

            print(f"\n{'='*60}")
            print("COMPARISON RESULTS")
            print(f"{'='*60}")
            print(f"File: {args.compare}")
            print(f"Users in file: {len(file_emails)}")
            print(f"Users in group: {len(users)}")

            print(f"\n\033[93mIn GROUP but NOT in FILE ({len(in_group_not_in_file)}):\033[0m")
            if in_group_not_in_file:
                for user in in_group_not_in_file:
                    print(f"  - {user['display_name']} ({user['email']})")
            else:
                print("  None")

            print(f"\n\033[96mIn FILE but NOT in GROUP ({len(in_file_not_in_group)}):\033[0m")
            if in_file_not_in_group:
                for email in sorted(in_file_not_in_group):
                    print(f"  - {email}")
            else:
                print("  None")

            comparison_results = {
                "file": args.compare,
                "file_user_count": len(file_emails),
                "in_group_not_in_file": [{"display_name": u['display_name'], "email": u['email']} for u in in_group_not_in_file],
                "in_file_not_in_group": list(in_file_not_in_group),
            }

    # Save to JSON if requested
    if args.output:
        output_data = {
            "timestamp": datetime.now().isoformat(),
            "group": {
                "id": group['id'],
                "displayName": group['displayName'],
                "description": group.get('description'),
            },
            "summary": summary,
            "disabled_users": [{"display_name": u['display_name'], "email": u['email']} for u in disabled_users],
            "users": users,
        }
        if comparison_results:
            output_data["comparison"] = comparison_results
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()
