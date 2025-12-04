#!/usr/bin/env python3
"""
Entra ID User Status Checker

Checks the status of user accounts in Microsoft Entra ID (Azure AD)
based on a list of email addresses.
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


def get_user_status(access_token: str, email: str) -> dict:
    """Get user status from Entra ID by email (searches both UPN and mail)."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    # Search user by userPrincipalName OR mail attribute
    url = f"{GRAPH_API_ENDPOINT}/users"
    params = {
        "$filter": f"userPrincipalName eq '{email}' or mail eq '{email}'",
        "$select": "id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,lastPasswordChangeDateTime,signInActivity"
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        users = data.get("value", [])

        if users:
            user_data = users[0]  # Take first match
            return {
                "email": email,
                "found": True,
                "display_name": user_data.get("displayName", "N/A"),
                "user_principal_name": user_data.get("userPrincipalName", "N/A"),
                "mail": user_data.get("mail", "N/A"),
                "account_enabled": user_data.get("accountEnabled", "N/A"),
                "created_date": user_data.get("createdDateTime", "N/A"),
                "last_password_change": user_data.get("lastPasswordChangeDateTime", "N/A"),
                "last_sign_in": user_data.get("signInActivity", {}).get(
                    "lastSignInDateTime", "N/A"
                ) if user_data.get("signInActivity") else "N/A",
                "last_non_interactive_sign_in": user_data.get("signInActivity", {}).get(
                    "lastNonInteractiveSignInDateTime", "N/A"
                ) if user_data.get("signInActivity") else "N/A",
            }
        else:
            return {
                "email": email,
                "found": False,
                "error": "User not found",
            }
    else:
        return {
            "email": email,
            "found": False,
            "error": f"API Error: {response.status_code} - {response.text}",
        }


def load_emails_from_file(filepath: str) -> list:
    """Load email addresses from a file (one per line)."""
    emails = []
    with open(filepath, "r") as f:
        for line in f:
            email = line.strip()
            if email and not email.startswith("#"):
                emails.append(email)
    return emails


def print_user_status(user: dict, verbose: bool = False):
    """Print user status in a formatted way."""
    if user["found"]:
        status = "ENABLED" if user["account_enabled"] else "DISABLED"
        status_color = "\033[92m" if user["account_enabled"] else "\033[91m"
        reset_color = "\033[0m"

        print(f"\n{'='*60}")
        print(f"Email: {user['email']}")
        print(f"Display Name: {user['display_name']}")
        print(f"Status: {status_color}{status}{reset_color}")

        if verbose:
            print(f"User Principal Name: {user['user_principal_name']}")
            print(f"Mail: {user['mail']}")
            print(f"Created: {user['created_date']}")
            print(f"Last Password Change: {user['last_password_change']}")
            print(f"Last Sign-In: {user['last_sign_in']}")
            print(f"Last Non-Interactive Sign-In: {user['last_non_interactive_sign_in']}")
    else:
        print(f"\n{'='*60}")
        print(f"Email: {user['email']}")
        print(f"Status: \033[93mNOT FOUND\033[0m")
        print(f"Error: {user.get('error', 'Unknown error')}")


def main():
    parser = argparse.ArgumentParser(
        description="Check Entra ID user account status from a list of emails"
    )
    parser.add_argument(
        "-f", "--file",
        default="users.txt",
        help="Path to file containing email addresses (default: users.txt)"
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
        "-e", "--email",
        help="Check a single email address instead of reading from file"
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

    # Get emails to check
    if args.email:
        emails = [args.email]
    else:
        if not os.path.exists(args.file):
            print(f"Error: File '{args.file}' not found.")
            sys.exit(1)
        emails = load_emails_from_file(args.file)

    if not emails:
        print("No email addresses to check.")
        sys.exit(0)

    print(f"Checking {len(emails)} user(s) in Entra ID...")

    try:
        access_token = get_access_token(tenant_id, client_id, client_secret)
    except Exception as e:
        print(f"Authentication failed: {e}")
        sys.exit(1)

    results = []
    summary = {"total": len(emails), "found": 0, "enabled": 0, "disabled": 0, "not_found": 0}

    for email in emails:
        user_status = get_user_status(access_token, email)
        results.append(user_status)
        print_user_status(user_status, args.verbose)

        if user_status["found"]:
            summary["found"] += 1
            if user_status["account_enabled"]:
                summary["enabled"] += 1
            else:
                summary["disabled"] += 1
        else:
            summary["not_found"] += 1

    # Print summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"Total checked: {summary['total']}")
    print(f"Found: {summary['found']}")
    print(f"  - Enabled: {summary['enabled']}")
    print(f"  - Disabled: {summary['disabled']}")
    print(f"Not found: {summary['not_found']}")

    # Save to JSON if requested
    if args.output:
        output_data = {
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
            "results": results,
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()
