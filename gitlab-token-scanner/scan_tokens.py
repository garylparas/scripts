#!/usr/bin/env python3
"""
GitLab Token Scanner

Scans all active group access tokens, project access tokens, and deploy tokens
in GitLab Cloud, showing who created the token and when.
"""

import os
import sys
import json
import argparse
from datetime import datetime
from typing import Optional

import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# GitLab API endpoint
GITLAB_API_URL = "https://gitlab.com/api/v4"


def make_request(endpoint: str, access_token: str, params: dict = None) -> Optional[dict | list]:
    """Make a request to the GitLab API."""
    headers = {
        "PRIVATE-TOKEN": access_token,
        "Content-Type": "application/json",
    }

    url = f"{GITLAB_API_URL}/{endpoint}"

    try:
        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            print(f"Error: Unauthorized. Check your GitLab access token.")
            return None
        elif response.status_code == 403:
            # No permission - return empty list
            return []
        elif response.status_code == 404:
            return []
        else:
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
        return None


def get_all_pages(endpoint: str, access_token: str, params: dict = None) -> list:
    """Get all pages of results from a paginated GitLab API endpoint."""
    headers = {
        "PRIVATE-TOKEN": access_token,
        "Content-Type": "application/json",
    }

    if params is None:
        params = {}

    params["per_page"] = 100
    params["page"] = 1

    all_results = []
    url = f"{GITLAB_API_URL}/{endpoint}"

    while True:
        try:
            response = requests.get(url, headers=headers, params=params)

            if response.status_code == 200:
                data = response.json()
                if not data:
                    break
                all_results.extend(data)

                # Check for next page
                if "x-next-page" in response.headers and response.headers["x-next-page"]:
                    params["page"] = int(response.headers["x-next-page"])
                else:
                    break
            elif response.status_code in [401, 403, 404]:
                break
            else:
                break
        except requests.exceptions.RequestException:
            break

    return all_results


def get_all_groups(access_token: str, min_access_level: int = 30) -> list:
    """Get all groups the user has access to (default: Developer level or higher)."""
    params = {"min_access_level": min_access_level}
    return get_all_pages("groups", access_token, params)


def get_all_projects(access_token: str, min_access_level: int = 30) -> list:
    """Get all projects the user has access to (default: Developer level or higher)."""
    params = {"min_access_level": min_access_level}
    return get_all_pages("projects", access_token, params)


def get_group_access_tokens(access_token: str, group_id: int) -> list:
    """Get all access tokens for a group."""
    result = make_request(f"groups/{group_id}/access_tokens", access_token)
    return result if result else []


def get_project_access_tokens(access_token: str, project_id: int) -> list:
    """Get all access tokens for a project."""
    result = make_request(f"projects/{project_id}/access_tokens", access_token)
    return result if result else []


def get_group_deploy_tokens(access_token: str, group_id: int) -> list:
    """Get all deploy tokens for a group."""
    result = make_request(f"groups/{group_id}/deploy_tokens", access_token)
    return result if result else []


def get_project_deploy_tokens(access_token: str, project_id: int) -> list:
    """Get all deploy tokens for a project."""
    result = make_request(f"projects/{project_id}/deploy_tokens", access_token)
    return result if result else []


def format_token_info(token: dict, token_type: str, parent_name: str, parent_type: str) -> dict:
    """Format token information into a standardized dict."""
    # Handle different date formats and field names
    created_at = token.get("created_at", "N/A")
    expires_at = token.get("expires_at", "Never")

    # Get creator info if available
    created_by = "N/A"
    if "created_by" in token and token["created_by"]:
        creator = token["created_by"]
        if isinstance(creator, dict):
            created_by = creator.get("username", creator.get("name", "N/A"))
        else:
            created_by = str(creator)

    # Determine if token is active
    is_active = token.get("active", True)
    is_revoked = token.get("revoked", False)

    # Check expiration
    is_expired = False
    if expires_at and expires_at != "Never":
        try:
            exp_date = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            is_expired = exp_date < datetime.now(exp_date.tzinfo)
        except (ValueError, TypeError):
            pass

    return {
        "token_type": token_type,
        "parent_type": parent_type,
        "parent_name": parent_name,
        "id": token.get("id", "N/A"),
        "name": token.get("name", "N/A"),
        "created_at": created_at,
        "expires_at": expires_at if expires_at else "Never",
        "created_by": created_by,
        "active": is_active and not is_revoked and not is_expired,
        "revoked": is_revoked,
        "is_expired": is_expired,
        "scopes": token.get("scopes", []),
        "access_level": token.get("access_level", "N/A"),
    }


def print_token_info(token: dict, verbose: bool = False):
    """Print token information in a formatted way."""
    active_status = token["active"]

    if active_status:
        status_color = "\033[92m"  # Green
        status_text = "ACTIVE"
    elif token["is_expired"]:
        status_color = "\033[91m"  # Red
        status_text = "EXPIRED"
    elif token["revoked"]:
        status_color = "\033[91m"  # Red
        status_text = "REVOKED"
    else:
        status_color = "\033[93m"  # Yellow
        status_text = "INACTIVE"

    reset_color = "\033[0m"

    print(f"\n{'-'*60}")
    print(f"Token Type: {token['token_type']}")
    print(f"{token['parent_type']}: {token['parent_name']}")
    print(f"Name: {token['name']}")
    print(f"Status: {status_color}{status_text}{reset_color}")
    print(f"Created At: {token['created_at']}")
    print(f"Expires At: {token['expires_at']}")
    print(f"Created By: {token['created_by']}")

    if verbose:
        print(f"Token ID: {token['id']}")
        print(f"Scopes: {', '.join(token['scopes']) if token['scopes'] else 'N/A'}")
        if token['access_level'] != "N/A":
            access_level_names = {
                10: "Guest",
                20: "Reporter",
                30: "Developer",
                40: "Maintainer",
                50: "Owner",
            }
            level_name = access_level_names.get(token['access_level'], str(token['access_level']))
            print(f"Access Level: {level_name}")


def main():
    parser = argparse.ArgumentParser(
        description="Scan GitLab Cloud for active access tokens and deploy tokens"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed token information"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output results to JSON file"
    )
    parser.add_argument(
        "--active-only",
        action="store_true",
        help="Only show active (non-expired, non-revoked) tokens"
    )
    parser.add_argument(
        "--groups-only",
        action="store_true",
        help="Only scan group tokens (skip projects)"
    )
    parser.add_argument(
        "--projects-only",
        action="store_true",
        help="Only scan project tokens (skip groups)"
    )
    parser.add_argument(
        "--skip-deploy-tokens",
        action="store_true",
        help="Skip scanning deploy tokens"
    )
    parser.add_argument(
        "--group-id",
        type=int,
        help="Scan only a specific group ID"
    )
    parser.add_argument(
        "--project-id",
        type=int,
        help="Scan only a specific project ID"
    )

    args = parser.parse_args()

    # Get GitLab access token from environment
    gitlab_token = os.getenv("GITLAB_ACCESS_TOKEN")

    if not gitlab_token:
        print("Error: Missing GITLAB_ACCESS_TOKEN environment variable.")
        print("Please set the following in your .env file:")
        print("  - GITLAB_ACCESS_TOKEN")
        sys.exit(1)

    all_tokens = []
    summary = {
        "group_access_tokens": {"total": 0, "active": 0},
        "project_access_tokens": {"total": 0, "active": 0},
        "group_deploy_tokens": {"total": 0, "active": 0},
        "project_deploy_tokens": {"total": 0, "active": 0},
    }

    # Scan groups
    if not args.projects_only:
        if args.group_id:
            # Scan specific group
            groups = [{"id": args.group_id, "full_path": f"Group {args.group_id}"}]
            print(f"Scanning specific group ID: {args.group_id}")
        else:
            print("Fetching groups...")
            groups = get_all_groups(gitlab_token)
            print(f"Found {len(groups)} group(s) to scan.")

        for i, group in enumerate(groups, 1):
            group_id = group["id"]
            group_name = group.get("full_path", group.get("name", str(group_id)))

            print(f"[{i}/{len(groups)}] Scanning group: {group_name}")

            # Get group access tokens
            group_tokens = get_group_access_tokens(gitlab_token, group_id)
            for token in group_tokens:
                token_info = format_token_info(token, "Group Access Token", group_name, "Group")

                if args.active_only and not token_info["active"]:
                    continue

                all_tokens.append(token_info)
                summary["group_access_tokens"]["total"] += 1
                if token_info["active"]:
                    summary["group_access_tokens"]["active"] += 1
                print_token_info(token_info, args.verbose)

            # Get group deploy tokens
            if not args.skip_deploy_tokens:
                deploy_tokens = get_group_deploy_tokens(gitlab_token, group_id)
                for token in deploy_tokens:
                    token_info = format_token_info(token, "Deploy Token", group_name, "Group")

                    if args.active_only and not token_info["active"]:
                        continue

                    all_tokens.append(token_info)
                    summary["group_deploy_tokens"]["total"] += 1
                    if token_info["active"]:
                        summary["group_deploy_tokens"]["active"] += 1
                    print_token_info(token_info, args.verbose)

    # Scan projects
    if not args.groups_only:
        if args.project_id:
            # Scan specific project
            projects = [{"id": args.project_id, "path_with_namespace": f"Project {args.project_id}"}]
            print(f"\nScanning specific project ID: {args.project_id}")
        else:
            print("\nFetching projects...")
            projects = get_all_projects(gitlab_token)
            print(f"Found {len(projects)} project(s) to scan.")

        for i, project in enumerate(projects, 1):
            project_id = project["id"]
            project_name = project.get("path_with_namespace", project.get("name", str(project_id)))

            print(f"[{i}/{len(projects)}] Scanning project: {project_name}")

            # Get project access tokens
            project_tokens = get_project_access_tokens(gitlab_token, project_id)
            for token in project_tokens:
                token_info = format_token_info(token, "Project Access Token", project_name, "Project")

                if args.active_only and not token_info["active"]:
                    continue

                all_tokens.append(token_info)
                summary["project_access_tokens"]["total"] += 1
                if token_info["active"]:
                    summary["project_access_tokens"]["active"] += 1
                print_token_info(token_info, args.verbose)

            # Get project deploy tokens
            if not args.skip_deploy_tokens:
                deploy_tokens = get_project_deploy_tokens(gitlab_token, project_id)
                for token in deploy_tokens:
                    token_info = format_token_info(token, "Deploy Token", project_name, "Project")

                    if args.active_only and not token_info["active"]:
                        continue

                    all_tokens.append(token_info)
                    summary["project_deploy_tokens"]["total"] += 1
                    if token_info["active"]:
                        summary["project_deploy_tokens"]["active"] += 1
                    print_token_info(token_info, args.verbose)

    # Print summary
    total_tokens = sum(s["total"] for s in summary.values())
    total_active = sum(s["active"] for s in summary.values())

    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"Total tokens found: {total_tokens}")
    print(f"Active tokens: {total_active}")
    print()

    if not args.projects_only:
        print(f"Group Access Tokens: {summary['group_access_tokens']['total']} (Active: {summary['group_access_tokens']['active']})")
        if not args.skip_deploy_tokens:
            print(f"Group Deploy Tokens: {summary['group_deploy_tokens']['total']} (Active: {summary['group_deploy_tokens']['active']})")

    if not args.groups_only:
        print(f"Project Access Tokens: {summary['project_access_tokens']['total']} (Active: {summary['project_access_tokens']['active']})")
        if not args.skip_deploy_tokens:
            print(f"Project Deploy Tokens: {summary['project_deploy_tokens']['total']} (Active: {summary['project_deploy_tokens']['active']})")

    # List active tokens by expiration
    if all_tokens:
        active_tokens = [t for t in all_tokens if t["active"]]
        if active_tokens:
            print(f"\n{'='*60}")
            print("ACTIVE TOKENS BY EXPIRATION")
            print(f"{'='*60}")

            # Sort by expiration date (Never expires last)
            def sort_key(t):
                if t["expires_at"] == "Never":
                    return datetime.max
                try:
                    return datetime.fromisoformat(t["expires_at"].replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    return datetime.max

            sorted_tokens = sorted(active_tokens, key=sort_key)

            for token in sorted_tokens:
                expires = token["expires_at"]
                if expires != "Never":
                    try:
                        exp_date = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                        days_remaining = (exp_date - datetime.now(exp_date.tzinfo)).days
                        if days_remaining <= 30:
                            expires = f"\033[93m{expires} ({days_remaining} days)\033[0m"
                        elif days_remaining <= 7:
                            expires = f"\033[91m{expires} ({days_remaining} days)\033[0m"
                        else:
                            expires = f"{expires} ({days_remaining} days)"
                    except (ValueError, TypeError):
                        pass

                print(f"  - [{token['token_type']}] {token['name']} ({token['parent_name']}) - Expires: {expires}")

    # Save to JSON if requested
    if args.output:
        output_data = {
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
            "tokens": all_tokens,
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2, default=str)
        print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()
