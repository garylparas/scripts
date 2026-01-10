#!/usr/bin/env python3
"""
GitLab Activity Scanner

Scans GitLab user and project activities using the GitLab Events API.
Also supports audit events (sign-ins, security events) via the Audit Events API.
Supports filtering by action type, target type, and date range.
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime, timedelta
from typing import Optional

import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# GitLab API endpoint
GITLAB_API_URL = os.getenv("GITLAB_API_URL", "https://gitlab.com/api/v4")

# Action types available in GitLab Events API
ACTION_TYPES = [
    "approved",
    "closed",
    "commented on",
    "created",
    "destroyed",
    "expired",
    "joined",
    "left",
    "merged",
    "pushed",
    "pushed new",
    "pushed to",
    "reopened",
    "updated",
]

# Target types available in GitLab Events API
TARGET_TYPES = [
    "epic",
    "issue",
    "merge_request",
    "milestone",
    "note",
    "project",
    "snippet",
    "user",
]

# Cache for IP geolocation lookups
_ip_cache = {}


def lookup_ip_countries_batch(ip_addresses: list) -> None:
    """
    Batch lookup countries for multiple IP addresses using ip-api.com batch endpoint.
    Results are stored in _ip_cache. Batch endpoint allows up to 100 IPs per request.
    Rate limit: 45 requests/minute, but batch counts as 1 request for up to 100 IPs.
    """
    # Filter out already cached and invalid IPs
    ips_to_lookup = [
        ip for ip in set(ip_addresses)
        if ip and ip != "N/A" and ip not in _ip_cache
    ]

    if not ips_to_lookup:
        return

    # Process in batches of 100 (ip-api.com limit)
    batch_size = 100
    for i in range(0, len(ips_to_lookup), batch_size):
        batch = ips_to_lookup[i:i + batch_size]

        try:
            # Batch endpoint uses POST with JSON array
            response = requests.post(
                "http://ip-api.com/batch",
                json=[{"query": ip, "fields": "status,country,query"} for ip in batch],
                timeout=10
            )
            if response.status_code == 200:
                results = response.json()
                for result in results:
                    ip = result.get("query")
                    if result.get("status") == "success":
                        _ip_cache[ip] = result.get("country", "Unknown")
                    else:
                        _ip_cache[ip] = "Unknown"
            else:
                # If batch fails, mark all as unknown
                for ip in batch:
                    _ip_cache[ip] = "Unknown"
        except requests.exceptions.RequestException:
            # On error, mark all as unknown
            for ip in batch:
                _ip_cache[ip] = "Unknown"


def lookup_ip_country(ip_address: str) -> str:
    """Get country for an IP address from cache (call lookup_ip_countries_batch first)."""
    if not ip_address or ip_address == "N/A":
        return "N/A"
    return _ip_cache.get(ip_address, "Unknown")


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
            return response.json(), response.headers
        elif response.status_code == 401:
            print("Error: Unauthorized. Check your GitLab access token.")
            return None, None
        elif response.status_code == 403:
            print("Error: Forbidden. Token may lack required scopes (read_user or api).")
            return None, None
        elif response.status_code == 404:
            return [], None
        else:
            print(f"Error: API returned status {response.status_code}")
            return None, None
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
        return None, None


def get_all_pages(endpoint: str, access_token: str, params: dict = None, max_pages: int = 100) -> list:
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
    pages_fetched = 0

    while pages_fetched < max_pages:
        try:
            response = requests.get(url, headers=headers, params=params)

            if response.status_code == 200:
                data = response.json()
                if not data:
                    break
                all_results.extend(data)
                pages_fetched += 1

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


def get_current_user(access_token: str) -> Optional[dict]:
    """Get the current authenticated user."""
    result, _ = make_request("user", access_token)
    return result


def get_user_by_username(access_token: str, username: str) -> Optional[dict]:
    """Get a user by username."""
    result, _ = make_request("users", access_token, {"username": username})
    if result and len(result) > 0:
        return result[0]
    return None


def get_user_events(access_token: str, user_id: int = None, action: str = None,
                    target_type: str = None, before: str = None, after: str = None,
                    sort: str = "desc", max_pages: int = 100) -> list:
    """Get events for a user or the authenticated user."""
    params = {"sort": sort}

    if action:
        params["action"] = action
    if target_type:
        params["target_type"] = target_type
    if before:
        params["before"] = before
    if after:
        params["after"] = after

    if user_id:
        endpoint = f"users/{user_id}/events"
    else:
        endpoint = "events"

    return get_all_pages(endpoint, access_token, params, max_pages)


def get_project_events(access_token: str, project_id: int, action: str = None,
                       target_type: str = None, before: str = None, after: str = None,
                       sort: str = "desc", max_pages: int = 100) -> list:
    """Get events for a specific project."""
    params = {"sort": sort}

    if action:
        params["action"] = action
    if target_type:
        params["target_type"] = target_type
    if before:
        params["before"] = before
    if after:
        params["after"] = after

    endpoint = f"projects/{project_id}/events"
    return get_all_pages(endpoint, access_token, params, max_pages)


def get_project_info(access_token: str, project_id: int) -> Optional[dict]:
    """Get project information including web_url."""
    result, _ = make_request(f"projects/{project_id}", access_token)
    return result


def get_project_by_path(access_token: str, project_path: str) -> Optional[dict]:
    """Get a project by its path (e.g., group/project)."""
    # URL encode the path (replace / with %2F)
    encoded_path = project_path.replace("/", "%2F")
    result, _ = make_request(f"projects/{encoded_path}", access_token)
    return result


def get_group_audit_events(access_token: str, group_id: int,
                           created_before: str = None, created_after: str = None,
                           max_pages: int = 100) -> list:
    """Get group-level audit events (requires owner access)."""
    params = {}

    if created_before:
        params["created_before"] = created_before
    if created_after:
        params["created_after"] = created_after

    return get_all_pages(f"groups/{group_id}/audit_events", access_token, params, max_pages)


def get_project_audit_events(access_token: str, project_id: int,
                             created_before: str = None, created_after: str = None,
                             max_pages: int = 100) -> list:
    """Get project-level audit events (requires maintainer access)."""
    params = {}

    if created_before:
        params["created_before"] = created_before
    if created_after:
        params["created_after"] = created_after

    return get_all_pages(f"projects/{project_id}/audit_events", access_token, params, max_pages)


def get_group_by_path(access_token: str, group_path: str) -> Optional[dict]:
    """Get a group by its path."""
    encoded_path = group_path.replace("/", "%2F")
    result, _ = make_request(f"groups/{encoded_path}", access_token)
    return result


def format_audit_event(event: dict) -> dict:
    """Format an audit event into a standardized dict."""
    details = event.get("details", {}) or {}
    registration_details = details.get("registration_details", {}) or {}

    # Extract author info from details
    author_id = event.get("author_id", "N/A")
    author_name = details.get("author_name", "N/A")
    author_username = registration_details.get("username", "N/A")
    author_email = details.get("author_email", "N/A")

    # Extract entity info
    entity_type = event.get("entity_type", "N/A")
    entity_path = details.get("entity_path", "N/A")

    # Extract target details
    target_type = details.get("target_type", "N/A")
    target_details = details.get("target_details", "N/A")
    custom_message = details.get("custom_message", "")
    ip_address = details.get("ip_address", "N/A")

    # Lookup country from IP address
    country = lookup_ip_country(ip_address)

    # Format created_at (GitLab returns UTC timestamps)
    created_at = event.get("created_at", "N/A")
    if created_at and created_at != "N/A":
        try:
            dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            created_at = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except:
            pass

    # Action is from event_name at top level
    action = event.get("event_name", "N/A")

    return {
        "EventId": event.get("id", "N/A"),
        "AuthorId": author_id,
        "AuthorUsername": author_username,
        "AuthorName": author_name,
        "AuthorEmail": author_email,
        "Action": action,
        "EntityType": entity_type,
        "EntityPath": entity_path,
        "TargetType": target_type,
        "TargetDetails": target_details,
        "IPAddress": ip_address,
        "Country": country,
        "CustomMessage": custom_message or "N/A",
        "CreatedAt": created_at,
    }


def format_event(event: dict, project_cache: dict = None) -> dict:
    """Format an event into a standardized dict."""
    # Extract author info
    author = event.get("author", {})
    author_username = event.get("author_username", author.get("username", "N/A"))
    author_name = author.get("name", "N/A")

    # Extract push data if available
    push_data = event.get("push_data", {})
    commit_count = push_data.get("commit_count", 0) if push_data else 0
    ref = push_data.get("ref", "") if push_data else ""
    ref_type = push_data.get("ref_type", "") if push_data else ""

    # Extract note data if available
    note = event.get("note", {})
    note_body = note.get("body", "")[:100] + "..." if note and len(note.get("body", "")) > 100 else note.get("body", "") if note else ""

    # Format created_at (GitLab returns UTC timestamps)
    created_at = event.get("created_at", "N/A")
    if created_at and created_at != "N/A":
        try:
            dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            created_at = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except:
            pass

    # Get project info from cache
    project_id = event.get("project_id")
    project_url = "N/A"
    project_name = "N/A"
    ref_url = "N/A"
    target_url = "N/A"

    if project_id and project_cache and project_id in project_cache:
        project_info = project_cache[project_id]
        project_url = project_info.get("web_url", "N/A")
        project_name = project_info.get("path_with_namespace", "N/A")

        # Build ref URL if we have a ref
        if ref and project_url != "N/A":
            if ref_type == "tag":
                ref_url = f"{project_url}/-/tags/{ref}"
            else:  # branch
                ref_url = f"{project_url}/-/tree/{ref}"

        # Build ref URL for merge requests and issues (override branch/tag ref)
        target_type = event.get("target_type")
        target_iid = event.get("target_iid")
        if project_url != "N/A" and target_iid:
            if target_type == "MergeRequest":
                ref = f"!{target_iid}"
                ref_url = f"{project_url}/-/merge_requests/{target_iid}"
            elif target_type == "Issue":
                ref = f"#{target_iid}"
                ref_url = f"{project_url}/-/issues/{target_iid}"

    return {
        "EventId": event.get("id", "N/A"),
        "AuthorUsername": author_username,
        "AuthorName": author_name,
        "Action": event.get("action_name", "N/A"),
        "TargetType": event.get("target_type", "N/A") or "N/A",
        "TargetTitle": event.get("target_title", "N/A") or "N/A",
        "TargetId": event.get("target_id", "N/A") or "N/A",
        "ProjectName": project_name,
        "ProjectUrl": project_url,
        "RefType": ref_type or "N/A",
        "Ref": ref or "N/A",
        "RefUrl": ref_url,
        "CommitCount": commit_count if commit_count else "N/A",
        "NotePreview": note_body or "N/A",
        "CreatedAt": created_at,
    }


def scan_activities(access_token: str, usernames: list = None, project_paths: list = None,
                    action: str = None, target_type: str = None, before: str = None,
                    after: str = None, days: int = None, max_pages: int = 100,
                    verbose: bool = False) -> dict:
    """Scan GitLab activities for specified users, projects, or authenticated user."""
    results = {
        "events": [],
        "scan_info": {
            "users_scanned": 0,
            "projects_scanned": 0,
            "total_events": 0,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filters": {
                "action": action or "all",
                "target_type": target_type or "all",
                "before": before or "N/A",
                "after": after or "N/A",
            }
        }
    }

    # Calculate date range if days specified
    if days:
        after = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        results["scan_info"]["filters"]["after"] = after

    # Get current user info
    current_user = get_current_user(access_token)
    if not current_user:
        print("Error: Could not authenticate with GitLab API")
        return results

    if verbose:
        print(f"Authenticated as: {current_user.get('username')}")

    # Collect all events first
    all_events = []

    # Scan projects if specified
    if project_paths:
        projects_to_scan = []
        for project_path in project_paths:
            project = get_project_by_path(access_token, project_path)
            if project:
                projects_to_scan.append(project)
                if verbose:
                    print(f"Found project: {project_path} (ID: {project.get('id')})")
            else:
                print(f"Warning: Project '{project_path}' not found")

        for idx, project in enumerate(projects_to_scan, 1):
            project_id = project.get("id")
            project_name = project.get("path_with_namespace")

            print(f"[{idx}/{len(projects_to_scan)}] Scanning activities for project: {project_name}")

            events = get_project_events(
                access_token,
                project_id=project_id,
                action=action,
                target_type=target_type,
                before=before,
                after=after,
                max_pages=max_pages
            )

            if verbose:
                print(f"  Found {len(events)} events")

            all_events.extend(events)
            results["scan_info"]["projects_scanned"] += 1
    else:
        # Scan users
        users_to_scan = []

        if usernames:
            # Scan specific users
            for username in usernames:
                user = get_user_by_username(access_token, username)
                if user:
                    users_to_scan.append(user)
                    if verbose:
                        print(f"Found user: {username} (ID: {user.get('id')})")
                else:
                    print(f"Warning: User '{username}' not found")
        else:
            # Scan authenticated user only
            users_to_scan.append(current_user)

        # Scan each user
        for idx, user in enumerate(users_to_scan, 1):
            user_id = user.get("id")
            username = user.get("username")

            print(f"[{idx}/{len(users_to_scan)}] Scanning activities for: {username}")

            events = get_user_events(
                access_token,
                user_id=user_id,
                action=action,
                target_type=target_type,
                before=before,
                after=after,
                max_pages=max_pages
            )

            if verbose:
                print(f"  Found {len(events)} events")

            all_events.extend(events)
            results["scan_info"]["users_scanned"] += 1

    # Build project cache for all unique project IDs
    project_ids = set(e.get("project_id") for e in all_events if e.get("project_id"))
    project_cache = {}

    if project_ids:
        print(f"Fetching info for {len(project_ids)} projects...")
        for idx, project_id in enumerate(project_ids, 1):
            if verbose:
                print(f"  [{idx}/{len(project_ids)}] Fetching project {project_id}")
            project_info = get_project_info(access_token, project_id)
            if project_info:
                project_cache[project_id] = project_info

    # Format all events with project cache
    for event in all_events:
        formatted = format_event(event, project_cache)
        results["events"].append(formatted)

    results["scan_info"]["total_events"] = len(results["events"])

    return results


def scan_audit_events(access_token: str, usernames: list = None, group_paths: list = None,
                      project_paths: list = None, before: str = None, after: str = None,
                      days: int = None, max_pages: int = 100, verbose: bool = False) -> dict:
    """Scan GitLab audit events for sign-ins and security events."""
    results = {
        "events": [],
        "scan_info": {
            "users_scanned": 0,
            "groups_scanned": 0,
            "projects_scanned": 0,
            "total_events": 0,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_type": "audit",
            "filters": {
                "before": before or "N/A",
                "after": after or "N/A",
            }
        }
    }

    # Calculate date range if days specified
    if days:
        after = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        results["scan_info"]["filters"]["after"] = after

    # Get current user info
    current_user = get_current_user(access_token)
    if not current_user:
        print("Error: Could not authenticate with GitLab API")
        return results

    if verbose:
        print(f"Authenticated as: {current_user.get('username')}")

    all_events = []

    # Get user IDs for filtering (used for local filtering at group/project level)
    user_ids_to_filter = set()
    if usernames:
        for username in usernames:
            user = get_user_by_username(access_token, username)
            if user:
                user_ids_to_filter.add(user.get("id"))
                if verbose:
                    print(f"Found user: {username} (ID: {user.get('id')})")
            else:
                print(f"Warning: User '{username}' not found")

    # Scan project audit events if projects specified
    if project_paths:
        projects_to_scan = []
        for project_path in project_paths:
            project = get_project_by_path(access_token, project_path)
            if project:
                projects_to_scan.append(project)
                if verbose:
                    print(f"Found project: {project_path} (ID: {project.get('id')})")
            else:
                print(f"Warning: Project '{project_path}' not found")

        for idx, project in enumerate(projects_to_scan, 1):
            project_id = project.get("id")
            project_name = project.get("path_with_namespace")

            print(f"[{idx}/{len(projects_to_scan)}] Scanning audit events for project: {project_name}")
            events = get_project_audit_events(
                access_token,
                project_id=project_id,
                created_before=before,
                created_after=after,
                max_pages=max_pages
            )

            # Filter by user locally if specified
            if user_ids_to_filter:
                events = [e for e in events if e.get("author_id") in user_ids_to_filter]

            if verbose:
                print(f"  Found {len(events)} audit events")
            all_events.extend(events)
            results["scan_info"]["projects_scanned"] += 1

    # Scan group audit events if groups specified
    elif group_paths:
        groups_to_scan = []
        for group_path in group_paths:
            group = get_group_by_path(access_token, group_path)
            if group:
                groups_to_scan.append(group)
                if verbose:
                    print(f"Found group: {group_path} (ID: {group.get('id')})")
            else:
                print(f"Warning: Group '{group_path}' not found")

        for idx, group in enumerate(groups_to_scan, 1):
            group_id = group.get("id")
            group_name = group.get("full_path")

            print(f"[{idx}/{len(groups_to_scan)}] Scanning audit events for group: {group_name}")
            events = get_group_audit_events(
                access_token,
                group_id=group_id,
                created_before=before,
                created_after=after,
                max_pages=max_pages
            )

            # Filter by user locally if specified
            if user_ids_to_filter:
                events = [e for e in events if e.get("author_id") in user_ids_to_filter]

            if verbose:
                print(f"  Found {len(events)} audit events")
            all_events.extend(events)
            results["scan_info"]["groups_scanned"] += 1

    else:
        # No groups or projects specified - require at least one
        print("Error: Audit events require --groups or --projects to be specified.")
        print("       Instance-level audit events are not available on GitLab cloud.")
        print()
        print("Examples:")
        print("  python scan_activities.py --audit --groups my-group --days 30")
        print("  python scan_activities.py --audit --projects group/project --days 30")
        return results

    # Batch lookup IP countries before formatting (more efficient, avoids rate limits)
    if all_events:
        ip_addresses = [
            event.get("details", {}).get("ip_address")
            for event in all_events
            if event.get("details", {}).get("ip_address")
        ]
        if ip_addresses:
            print(f"Looking up countries for {len(set(ip_addresses))} unique IP addresses...")
            lookup_ip_countries_batch(ip_addresses)

    # Format all audit events
    for event in all_events:
        formatted = format_audit_event(event)
        results["events"].append(formatted)

    results["scan_info"]["total_events"] = len(results["events"])

    return results


def export_audit_to_html(results: dict, filename: str):
    """Export audit results to interactive HTML report."""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitLab Audit Events Report</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            color: #292961;
            border-bottom: 3px solid #fc6d26;
            padding-bottom: 10px;
        }
        .summary {
            background-color: #fff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 10px;
        }
        .summary-item {
            text-align: center;
            padding: 10px;
            background: #f9f9f9;
            border-radius: 5px;
        }
        .summary-item .count {
            font-size: 24px;
            font-weight: bold;
            color: #292961;
        }
        .summary-item .label {
            font-size: 12px;
            color: #666;
        }
        .filters {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: center;
            margin-bottom: 15px;
            padding: 15px;
            background: #fff;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
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
        .filter-group input { width: 200px; }
        .filter-group select { min-width: 150px; }
        .btn-clear {
            padding: 8px 16px;
            background-color: #292961;
            color: #fff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            margin-top: 18px;
        }
        .btn-clear:hover { background-color: #3d3d7a; }
        .table-container {
            overflow-x: auto;
            max-height: 70vh;
            overflow-y: auto;
            background: #fff;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            table-layout: auto;
        }
        th {
            background-color: #292961;
            color: #fff;
            padding: 12px 8px;
            text-align: left;
            font-size: 12px;
            cursor: pointer;
            user-select: none;
            position: sticky;
            top: 0;
            z-index: 10;
            min-width: 60px;
            overflow: hidden;
        }
        .resize-handle {
            position: absolute;
            right: 0;
            top: 0;
            bottom: 0;
            width: 5px;
            cursor: col-resize;
            background: transparent;
        }
        .resize-handle:hover {
            background: rgba(252, 109, 38, 0.5);
        }
        th:hover { background-color: #3d3d7a; }
        th .sort-icon { margin-left: 5px; font-size: 10px; }
        th.sort-asc .sort-icon::after { content: ' ▲'; }
        th.sort-desc .sort-icon::after { content: ' ▼'; }
        th:not(.sort-asc):not(.sort-desc) .sort-icon::after { content: ' ⇅'; opacity: 0.5; }
        td {
            padding: 10px 8px;
            border-bottom: 1px solid #ddd;
            font-size: 12px;
            white-space: normal;
            word-wrap: break-word;
            max-width: 300px;
            vertical-align: top;
        }
        tr:hover { background-color: #f9f9f9; }
        tr.hidden { display: none; }
        .action-login { color: #1aaa55; font-weight: bold; }
        .action-logout { color: #1f78d1; font-weight: bold; }
        .action-failed { color: #db3b21; font-weight: bold; }
        .action-security { color: #fc6d26; font-weight: bold; }
        td a { color: #1f78d1; text-decoration: none; }
        td a:hover { text-decoration: underline; }
        .timestamp { color: #879596; font-size: 12px; margin-bottom: 20px; }
        .result-count { color: #666; font-size: 13px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <h1>GitLab Audit Events Report</h1>
    <p class="timestamp">Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>

    <div class="summary">
        <strong>Summary</strong>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="count">""" + (str(results["scan_info"]["groups_scanned"]) if results["scan_info"]["groups_scanned"] > 0 else str(results["scan_info"]["users_scanned"])) + """</div>
                <div class="label">""" + ("Groups Scanned" if results["scan_info"]["groups_scanned"] > 0 else "Users Scanned") + """</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(results["scan_info"]["total_events"]) + """</div>
                <div class="label">Total Events</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(set(e["Action"] for e in results.get("events", [])))) + """</div>
                <div class="label">Action Types</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(set(e["AuthorUsername"] for e in results.get("events", []) if e["AuthorUsername"] != "N/A"))) + """</div>
                <div class="label">Users</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(set(e["Country"] for e in results.get("events", []) if e["Country"] != "N/A" and e["Country"] != "Unknown"))) + """</div>
                <div class="label">Countries</div>
            </div>
        </div>
        <div style="margin-top: 10px; font-size: 12px; color: #666;">
            <strong>Date Range:</strong> """ + results["scan_info"]["filters"]["after"] + """ to """ + (results["scan_info"]["filters"]["before"] if results["scan_info"]["filters"]["before"] != "N/A" else "now") + """
        </div>
    </div>

    <div class="filters">
        <div class="filter-group">
            <label>Search</label>
            <input type="text" id="searchInput" placeholder="Search all columns..." onkeyup="filterTable()">
        </div>
        <div class="filter-group">
            <label>Author</label>
            <select id="authorFilter" onchange="filterTable()">
                <option value="">All Authors</option>
            </select>
        </div>
        <div class="filter-group">
            <label>Action</label>
            <select id="actionFilter" onchange="filterTable()">
                <option value="">All Actions</option>
            </select>
        </div>
        <div class="filter-group">
            <label>Entity Type</label>
            <select id="entityFilter" onchange="filterTable()">
                <option value="">All Types</option>
            </select>
        </div>
        <div class="filter-group">
            <label>Country</label>
            <select id="countryFilter" onchange="filterTable()">
                <option value="">All Countries</option>
            </select>
        </div>
        <div class="filter-group">
            <label>Date Range</label>
            <select id="dateRangeFilter" onchange="filterTable()">
                <option value="">All Time</option>
                <option value="1">Last 1 Day</option>
                <option value="3">Last 3 Days</option>
                <option value="7">Last 7 Days</option>
                <option value="30">Last 30 Days</option>
                <option value="90">Last 90 Days</option>
            </select>
        </div>
        <button class="btn-clear" onclick="clearFilters()">Clear Filters</button>
    </div>

    <div class="result-count">Showing <span id="visibleCount">0</span> of """ + str(len(results.get("events", []))) + """ events</div>

    <div class="table-container">
        <table id="eventsTable">
            <thead>
                <tr>
                    <th>Event ID<span class="sort-icon"></span></th>
                    <th>Author<span class="sort-icon"></span></th>
                    <th>Author Email<span class="sort-icon"></span></th>
                    <th>Action<span class="sort-icon"></span></th>
                    <th>Entity Type<span class="sort-icon"></span></th>
                    <th>Entity Path<span class="sort-icon"></span></th>
                    <th>Target Type<span class="sort-icon"></span></th>
                    <th>Target Details<span class="sort-icon"></span></th>
                    <th>IP Address<span class="sort-icon"></span></th>
                    <th>Country<span class="sort-icon"></span></th>
                    <th>Created At<span class="sort-icon"></span></th>
                </tr>
            </thead>
            <tbody>
"""

    for event in results.get("events", []):
        action = str(event["Action"]).lower()
        action_class = ""
        if "login" in action or "sign" in action or "authenticated" in action:
            action_class = "action-login"
        elif "logout" in action:
            action_class = "action-logout"
        elif "failed" in action or "denied" in action:
            action_class = "action-failed"
        elif "password" in action or "2fa" in action or "key" in action:
            action_class = "action-security"

        html += f"""                <tr>
                    <td>{event['EventId']}</td>
                    <td>{event['AuthorUsername']}</td>
                    <td>{event['AuthorEmail']}</td>
                    <td class="{action_class}">{event['Action']}</td>
                    <td>{event['EntityType']}</td>
                    <td>{event['EntityPath']}</td>
                    <td>{event['TargetType']}</td>
                    <td>{event['TargetDetails']}</td>
                    <td>{event['IPAddress']}</td>
                    <td>{event['Country']}</td>
                    <td>{event['CreatedAt']}</td>
                </tr>
"""

    html += """            </tbody>
        </table>
    </div>

<script>
function filterTable() {
    const search = document.getElementById('searchInput').value.toLowerCase();
    const author = document.getElementById('authorFilter').value;
    const action = document.getElementById('actionFilter').value;
    const entity = document.getElementById('entityFilter').value;
    const country = document.getElementById('countryFilter').value;
    const dateRange = document.getElementById('dateRangeFilter').value;

    const table = document.getElementById('eventsTable');
    const rows = table.querySelectorAll('tbody tr');
    let visibleCount = 0;

    const now = new Date();
    const cutoffDate = dateRange ? new Date(now.getTime() - (parseInt(dateRange) * 24 * 60 * 60 * 1000)) : null;

    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        const text = Array.from(cells).map(c => c.textContent.toLowerCase()).join(' ');
        const rowAuthor = cells[1].textContent;
        const rowAction = cells[3].textContent;
        const rowEntity = cells[4].textContent;
        const rowCountry = cells[9].textContent;
        const rowDate = cells[10].textContent;

        let show = text.includes(search);
        if (author && rowAuthor !== author) show = false;
        if (action && rowAction !== action) show = false;
        if (entity && rowEntity !== entity) show = false;
        if (country && rowCountry !== country) show = false;

        if (cutoffDate && rowDate) {
            const cleaned = rowDate.replace(' UTC', '').replace(' ', 'T') + 'Z';
            const eventDate = new Date(cleaned);
            if (eventDate < cutoffDate) show = false;
        }

        row.classList.toggle('hidden', !show);
        if (show) visibleCount++;
    });

    document.getElementById('visibleCount').textContent = visibleCount;
}

function clearFilters() {
    document.getElementById('searchInput').value = '';
    document.getElementById('authorFilter').value = '';
    document.getElementById('actionFilter').value = '';
    document.getElementById('entityFilter').value = '';
    document.getElementById('countryFilter').value = '';
    document.getElementById('dateRangeFilter').value = '';
    filterTable();
}

function populateFilters() {
    const table = document.getElementById('eventsTable');
    const rows = table.querySelectorAll('tbody tr');
    const authors = new Set();
    const actions = new Set();
    const entities = new Set();
    const countries = new Set();

    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length > 9) {
            authors.add(cells[1].textContent);
            actions.add(cells[3].textContent);
            entities.add(cells[4].textContent);
            countries.add(cells[9].textContent);
        }
    });

    const authorSelect = document.getElementById('authorFilter');
    const actionSelect = document.getElementById('actionFilter');
    const entitySelect = document.getElementById('entityFilter');
    const countrySelect = document.getElementById('countryFilter');

    [...authors].sort().forEach(a => {
        if (a !== 'N/A') {
            const opt = document.createElement('option');
            opt.value = a;
            opt.textContent = a;
            authorSelect.appendChild(opt);
        }
    });

    [...actions].sort().forEach(a => {
        if (a !== 'N/A') {
            const opt = document.createElement('option');
            opt.value = a;
            opt.textContent = a;
            actionSelect.appendChild(opt);
        }
    });

    [...entities].sort().forEach(e => {
        if (e !== 'N/A') {
            const opt = document.createElement('option');
            opt.value = e;
            opt.textContent = e;
            entitySelect.appendChild(opt);
        }
    });

    [...countries].sort().forEach(c => {
        if (c !== 'N/A' && c !== 'Unknown') {
            const opt = document.createElement('option');
            opt.value = c;
            opt.textContent = c;
            countrySelect.appendChild(opt);
        }
    });
}

function isDateValue(val) {
    return /^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}/.test(val);
}

function parseDate(val) {
    // Handle "2024-01-15 10:30:00 UTC" format
    const cleaned = val.replace(' UTC', '').replace(' ', 'T') + 'Z';
    return new Date(cleaned).getTime();
}

function sortTable(colIndex) {
    const table = document.getElementById('eventsTable');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const th = table.querySelectorAll('th')[colIndex];

    const isAsc = th.classList.contains('sort-asc');
    table.querySelectorAll('th').forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
    th.classList.add(isAsc ? 'sort-desc' : 'sort-asc');

    rows.sort((a, b) => {
        let aVal = a.cells[colIndex].textContent.trim();
        let bVal = b.cells[colIndex].textContent.trim();

        // Check if this is a date column
        if (isDateValue(aVal) && isDateValue(bVal)) {
            const aDate = parseDate(aVal);
            const bDate = parseDate(bVal);
            return isAsc ? bDate - aDate : aDate - bDate;
        }

        // Check if numeric
        const aNum = parseFloat(aVal.replace(/[^0-9.-]/g, ''));
        const bNum = parseFloat(bVal.replace(/[^0-9.-]/g, ''));
        if (!isNaN(aNum) && !isNaN(bNum) && aVal.match(/^[\\d.-]+$/)) {
            return isAsc ? bNum - aNum : aNum - bNum;
        }

        return isAsc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
    });

    rows.forEach(row => tbody.appendChild(row));
}

function initResizableColumns() {
    const table = document.getElementById('eventsTable');
    const headers = table.querySelectorAll('th');

    headers.forEach(th => {
        const handle = document.createElement('div');
        handle.className = 'resize-handle';
        th.appendChild(handle);

        let startX, startWidth;

        handle.addEventListener('mousedown', (e) => {
            e.stopPropagation();
            startX = e.pageX;
            startWidth = th.offsetWidth;

            const onMouseMove = (e) => {
                const width = startWidth + (e.pageX - startX);
                if (width >= 60) {
                    th.style.width = width + 'px';
                    th.style.minWidth = width + 'px';
                }
            };

            const onMouseUp = () => {
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
            };

            document.addEventListener('mousemove', onMouseMove);
            document.addEventListener('mouseup', onMouseUp);
        });
    });
}

document.addEventListener('DOMContentLoaded', function() {
    populateFilters();

    const table = document.getElementById('eventsTable');
    table.querySelectorAll('th').forEach((th, index) => {
        th.addEventListener('click', (e) => {
            if (!e.target.classList.contains('resize-handle')) {
                sortTable(index);
            }
        });
    });

    initResizableColumns();
    filterTable();
});
</script>
</body>
</html>
"""

    with open(filename, "w") as f:
        f.write(html)
    print(f"HTML report saved to: {filename}")


def export_combined_to_html(activity_results: dict, audit_results: dict, filename: str):
    """Export both activity and audit results to interactive HTML report with tabs."""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitLab Activity & Audit Report</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            color: #292961;
            border-bottom: 3px solid #fc6d26;
            padding-bottom: 10px;
        }
        .tabs {
            display: flex;
            gap: 5px;
            margin-bottom: 0;
            border-bottom: 2px solid #292961;
        }
        .tab-btn {
            padding: 12px 24px;
            background-color: #e0e0e0;
            border: none;
            border-radius: 5px 5px 0 0;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
            color: #666;
            transition: all 0.2s;
        }
        .tab-btn:hover {
            background-color: #d0d0d0;
        }
        .tab-btn.active {
            background-color: #292961;
            color: #fff;
        }
        .tab-btn .badge {
            background-color: rgba(255,255,255,0.3);
            padding: 2px 8px;
            border-radius: 10px;
            margin-left: 8px;
            font-size: 12px;
        }
        .tab-btn.active .badge {
            background-color: #fc6d26;
        }
        .tab-content {
            display: none;
            padding: 20px;
            background: #fff;
            border-radius: 0 5px 5px 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .tab-content.active {
            display: block;
        }
        .summary {
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-top: 10px;
        }
        .summary-item {
            text-align: center;
            padding: 10px;
            background: #fff;
            border-radius: 5px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.05);
        }
        .summary-item .count {
            font-size: 24px;
            font-weight: bold;
            color: #292961;
        }
        .summary-item .label {
            font-size: 11px;
            color: #666;
        }
        .filters {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: center;
            margin-bottom: 15px;
            padding: 15px;
            background: #f9f9f9;
            border-radius: 5px;
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
        .filter-group input { width: 200px; }
        .filter-group select { min-width: 150px; }
        .btn-clear {
            padding: 8px 16px;
            background-color: #292961;
            color: #fff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            margin-top: 18px;
        }
        .btn-clear:hover { background-color: #3d3d7a; }
        .table-container {
            overflow-x: auto;
            max-height: 60vh;
            overflow-y: auto;
            background: #fff;
            border-radius: 5px;
            border: 1px solid #e0e0e0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            table-layout: auto;
        }
        th {
            background-color: #292961;
            color: #fff;
            padding: 12px 8px;
            text-align: left;
            font-size: 12px;
            cursor: pointer;
            user-select: none;
            position: sticky;
            top: 0;
            z-index: 10;
            min-width: 60px;
            overflow: hidden;
        }
        .resize-handle {
            position: absolute;
            right: 0;
            top: 0;
            bottom: 0;
            width: 5px;
            cursor: col-resize;
            background: transparent;
        }
        .resize-handle:hover {
            background: rgba(252, 109, 38, 0.5);
        }
        th:hover { background-color: #3d3d7a; }
        th .sort-icon { margin-left: 5px; font-size: 10px; }
        th.sort-asc .sort-icon::after { content: ' ▲'; }
        th.sort-desc .sort-icon::after { content: ' ▼'; }
        th:not(.sort-asc):not(.sort-desc) .sort-icon::after { content: ' ⇅'; opacity: 0.5; }
        td {
            padding: 10px 8px;
            border-bottom: 1px solid #ddd;
            font-size: 12px;
            white-space: normal;
            word-wrap: break-word;
            max-width: 300px;
            vertical-align: top;
        }
        tr:hover { background-color: #f9f9f9; }
        tr.hidden { display: none; }
        .action-pushed, .action-merged { color: #1aaa55; font-weight: bold; }
        .action-created, .action-opened { color: #1f78d1; font-weight: bold; }
        .action-closed, .action-destroyed { color: #db3b21; font-weight: bold; }
        .action-commented { color: #fc6d26; font-weight: bold; }
        .action-login { color: #1aaa55; font-weight: bold; }
        .action-logout { color: #1f78d1; font-weight: bold; }
        .action-failed { color: #db3b21; font-weight: bold; }
        .action-security { color: #fc6d26; font-weight: bold; }
        td a { color: #1f78d1; text-decoration: none; }
        td a:hover { text-decoration: underline; }
        .timestamp { color: #879596; font-size: 12px; margin-bottom: 20px; }
        .result-count { color: #666; font-size: 13px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <h1>GitLab Activity & Audit Report</h1>
    <p class="timestamp">Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>

    <div class="tabs">
        <button class="tab-btn active" onclick="showTab('activity')">
            Activity Events<span class="badge">""" + str(len(activity_results.get("events", []))) + """</span>
        </button>
        <button class="tab-btn" onclick="showTab('audit')">
            Audit Events<span class="badge">""" + str(len(audit_results.get("events", []))) + """</span>
        </button>
    </div>

    <!-- Activity Events Tab -->
    <div id="activity-tab" class="tab-content active">
        <div class="summary">
            <strong>Activity Summary</strong>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="count">""" + str(len(activity_results.get("events", []))) + """</div>
                    <div class="label">Total Events</div>
                </div>
                <div class="summary-item">
                    <div class="count">""" + str(len(set(e["Action"] for e in activity_results.get("events", [])))) + """</div>
                    <div class="label">Action Types</div>
                </div>
                <div class="summary-item">
                    <div class="count">""" + str(len(set(e["ProjectName"] for e in activity_results.get("events", []) if e["ProjectName"] != "N/A"))) + """</div>
                    <div class="label">Projects</div>
                </div>
                <div class="summary-item">
                    <div class="count">""" + str(len(set(e["AuthorUsername"] for e in activity_results.get("events", []) if e["AuthorUsername"] != "N/A"))) + """</div>
                    <div class="label">Authors</div>
                </div>
            </div>
            <div style="margin-top: 10px; font-size: 12px; color: #666;">
                <strong>Date Range:</strong> """ + activity_results["scan_info"]["filters"]["after"] + """ to """ + (activity_results["scan_info"]["filters"]["before"] if activity_results["scan_info"]["filters"]["before"] != "N/A" else "now") + """
            </div>
        </div>

        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="activitySearch" placeholder="Search..." onkeyup="filterActivityTable()">
            </div>
            <div class="filter-group">
                <label>Author</label>
                <select id="activityAuthorFilter" onchange="filterActivityTable()">
                    <option value="">All Authors</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Action</label>
                <select id="activityActionFilter" onchange="filterActivityTable()">
                    <option value="">All Actions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Project</label>
                <select id="activityProjectFilter" onchange="filterActivityTable()">
                    <option value="">All Projects</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Date Range</label>
                <select id="activityDateRangeFilter" onchange="filterActivityTable()">
                    <option value="">All Time</option>
                    <option value="1">Last 1 Day</option>
                    <option value="3">Last 3 Days</option>
                    <option value="7">Last 7 Days</option>
                    <option value="30">Last 30 Days</option>
                    <option value="90">Last 90 Days</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearActivityFilters()">Clear</button>
        </div>

        <div class="result-count">Showing <span id="activityVisibleCount">0</span> of """ + str(len(activity_results.get("events", []))) + """ events</div>

        <div class="table-container">
            <table id="activityTable">
                <thead>
                    <tr>
                        <th>Event ID<span class="sort-icon"></span></th>
                        <th>Author<span class="sort-icon"></span></th>
                        <th>Action<span class="sort-icon"></span></th>
                        <th>Target Type<span class="sort-icon"></span></th>
                        <th>Target Title<span class="sort-icon"></span></th>
                        <th>Project<span class="sort-icon"></span></th>
                        <th>Ref<span class="sort-icon"></span></th>
                        <th>Created At<span class="sort-icon"></span></th>
                    </tr>
                </thead>
                <tbody>
"""

    # Activity events rows
    for event in activity_results.get("events", []):
        action = event["Action"]
        action_class = ""
        if "push" in action.lower():
            action_class = "action-pushed"
        elif "merge" in action.lower():
            action_class = "action-merged"
        elif "create" in action.lower() or "open" in action.lower():
            action_class = "action-created"
        elif "close" in action.lower() or "destroy" in action.lower():
            action_class = "action-closed"
        elif "comment" in action.lower():
            action_class = "action-commented"

        project_name = event['ProjectName']
        project_url = event['ProjectUrl']
        if project_url and project_url != "N/A":
            project_cell = f'<a href="{project_url}" target="_blank">{project_name}</a>'
        else:
            project_cell = project_name

        ref = event['Ref']
        ref_url = event['RefUrl']
        if ref_url and ref_url != "N/A":
            ref_cell = f'<a href="{ref_url}" target="_blank">{ref}</a>'
        else:
            ref_cell = ref

        html += f"""                    <tr>
                        <td>{event['EventId']}</td>
                        <td>{event['AuthorUsername']}</td>
                        <td class="{action_class}">{event['Action']}</td>
                        <td>{event['TargetType']}</td>
                        <td>{event['TargetTitle']}</td>
                        <td>{project_cell}</td>
                        <td>{ref_cell}</td>
                        <td>{event['CreatedAt']}</td>
                    </tr>
"""

    html += """                </tbody>
            </table>
        </div>
    </div>

    <!-- Audit Events Tab -->
    <div id="audit-tab" class="tab-content">
        <div class="summary">
            <strong>Audit Summary</strong>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="count">""" + str(len(audit_results.get("events", []))) + """</div>
                    <div class="label">Total Events</div>
                </div>
                <div class="summary-item">
                    <div class="count">""" + str(len(set(e["Action"] for e in audit_results.get("events", [])))) + """</div>
                    <div class="label">Action Types</div>
                </div>
                <div class="summary-item">
                    <div class="count">""" + str(len(set(e["EntityType"] for e in audit_results.get("events", []) if e["EntityType"] != "N/A"))) + """</div>
                    <div class="label">Entity Types</div>
                </div>
                <div class="summary-item">
                    <div class="count">""" + str(len(set(e["AuthorUsername"] for e in audit_results.get("events", []) if e["AuthorUsername"] != "N/A"))) + """</div>
                    <div class="label">Authors</div>
                </div>
                <div class="summary-item">
                    <div class="count">""" + str(len(set(e["Country"] for e in audit_results.get("events", []) if e["Country"] != "N/A" and e["Country"] != "Unknown"))) + """</div>
                    <div class="label">Countries</div>
                </div>
            </div>
            <div style="margin-top: 10px; font-size: 12px; color: #666;">
                <strong>Date Range:</strong> """ + audit_results["scan_info"]["filters"]["after"] + """ to """ + (audit_results["scan_info"]["filters"]["before"] if audit_results["scan_info"]["filters"]["before"] != "N/A" else "now") + """
            </div>
        </div>

        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="auditSearch" placeholder="Search..." onkeyup="filterAuditTable()">
            </div>
            <div class="filter-group">
                <label>Author</label>
                <select id="auditAuthorFilter" onchange="filterAuditTable()">
                    <option value="">All Authors</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Action</label>
                <select id="auditActionFilter" onchange="filterAuditTable()">
                    <option value="">All Actions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Entity Type</label>
                <select id="auditEntityFilter" onchange="filterAuditTable()">
                    <option value="">All Types</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Country</label>
                <select id="auditCountryFilter" onchange="filterAuditTable()">
                    <option value="">All Countries</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Date Range</label>
                <select id="auditDateRangeFilter" onchange="filterAuditTable()">
                    <option value="">All Time</option>
                    <option value="1">Last 1 Day</option>
                    <option value="3">Last 3 Days</option>
                    <option value="7">Last 7 Days</option>
                    <option value="30">Last 30 Days</option>
                    <option value="90">Last 90 Days</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearAuditFilters()">Clear</button>
        </div>

        <div class="result-count">Showing <span id="auditVisibleCount">0</span> of """ + str(len(audit_results.get("events", []))) + """ events</div>

        <div class="table-container">
            <table id="auditTable">
                <thead>
                    <tr>
                        <th>Event ID<span class="sort-icon"></span></th>
                        <th>Author<span class="sort-icon"></span></th>
                        <th>Author Email<span class="sort-icon"></span></th>
                        <th>Action<span class="sort-icon"></span></th>
                        <th>Entity Type<span class="sort-icon"></span></th>
                        <th>Entity Path<span class="sort-icon"></span></th>
                        <th>Target Type<span class="sort-icon"></span></th>
                        <th>Target Details<span class="sort-icon"></span></th>
                        <th>IP Address<span class="sort-icon"></span></th>
                        <th>Country<span class="sort-icon"></span></th>
                        <th>Created At<span class="sort-icon"></span></th>
                    </tr>
                </thead>
                <tbody>
"""

    # Audit events rows
    for event in audit_results.get("events", []):
        action = str(event["Action"]).lower()
        action_class = ""
        if "login" in action or "sign" in action or "authenticated" in action:
            action_class = "action-login"
        elif "logout" in action:
            action_class = "action-logout"
        elif "failed" in action or "denied" in action:
            action_class = "action-failed"
        elif "password" in action or "2fa" in action or "key" in action:
            action_class = "action-security"

        html += f"""                    <tr>
                        <td>{event['EventId']}</td>
                        <td>{event['AuthorUsername']}</td>
                        <td>{event['AuthorEmail']}</td>
                        <td class="{action_class}">{event['Action']}</td>
                        <td>{event['EntityType']}</td>
                        <td>{event['EntityPath']}</td>
                        <td>{event['TargetType']}</td>
                        <td>{event['TargetDetails']}</td>
                        <td>{event['IPAddress']}</td>
                        <td>{event['Country']}</td>
                        <td>{event['CreatedAt']}</td>
                    </tr>
"""

    html += """                </tbody>
            </table>
        </div>
    </div>

<script>
function showTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(tabName + '-tab').classList.add('active');
    event.target.classList.add('active');
}

// Activity table functions
function filterActivityTable() {
    const search = document.getElementById('activitySearch').value.toLowerCase();
    const author = document.getElementById('activityAuthorFilter').value;
    const action = document.getElementById('activityActionFilter').value;
    const project = document.getElementById('activityProjectFilter').value;
    const dateRange = document.getElementById('activityDateRangeFilter').value;

    const rows = document.querySelectorAll('#activityTable tbody tr');
    let visibleCount = 0;

    const now = new Date();
    const cutoffDate = dateRange ? new Date(now.getTime() - (parseInt(dateRange) * 24 * 60 * 60 * 1000)) : null;

    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        const text = Array.from(cells).map(c => c.textContent.toLowerCase()).join(' ');
        const rowAuthor = cells[1].textContent;
        const rowAction = cells[2].textContent;
        const rowProject = cells[5].textContent;
        const rowDate = cells[7].textContent;

        let show = text.includes(search);
        if (author && rowAuthor !== author) show = false;
        if (action && rowAction !== action) show = false;
        if (project && rowProject !== project) show = false;

        if (cutoffDate && rowDate) {
            const cleaned = rowDate.replace(' UTC', '').replace(' ', 'T') + 'Z';
            const eventDate = new Date(cleaned);
            if (eventDate < cutoffDate) show = false;
        }

        row.classList.toggle('hidden', !show);
        if (show) visibleCount++;
    });

    document.getElementById('activityVisibleCount').textContent = visibleCount;
}

function clearActivityFilters() {
    document.getElementById('activitySearch').value = '';
    document.getElementById('activityAuthorFilter').value = '';
    document.getElementById('activityActionFilter').value = '';
    document.getElementById('activityProjectFilter').value = '';
    document.getElementById('activityDateRangeFilter').value = '';
    filterActivityTable();
}

// Audit table functions
function filterAuditTable() {
    const search = document.getElementById('auditSearch').value.toLowerCase();
    const author = document.getElementById('auditAuthorFilter').value;
    const action = document.getElementById('auditActionFilter').value;
    const entity = document.getElementById('auditEntityFilter').value;
    const country = document.getElementById('auditCountryFilter').value;
    const dateRange = document.getElementById('auditDateRangeFilter').value;

    const rows = document.querySelectorAll('#auditTable tbody tr');
    let visibleCount = 0;

    const now = new Date();
    const cutoffDate = dateRange ? new Date(now.getTime() - (parseInt(dateRange) * 24 * 60 * 60 * 1000)) : null;

    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        const text = Array.from(cells).map(c => c.textContent.toLowerCase()).join(' ');
        const rowAuthor = cells[1].textContent;
        const rowAction = cells[3].textContent;
        const rowEntity = cells[4].textContent;
        const rowCountry = cells[9].textContent;
        const rowDate = cells[10].textContent;

        let show = text.includes(search);
        if (author && rowAuthor !== author) show = false;
        if (action && rowAction !== action) show = false;
        if (entity && rowEntity !== entity) show = false;
        if (country && rowCountry !== country) show = false;

        if (cutoffDate && rowDate) {
            const cleaned = rowDate.replace(' UTC', '').replace(' ', 'T') + 'Z';
            const eventDate = new Date(cleaned);
            if (eventDate < cutoffDate) show = false;
        }

        row.classList.toggle('hidden', !show);
        if (show) visibleCount++;
    });

    document.getElementById('auditVisibleCount').textContent = visibleCount;
}

function clearAuditFilters() {
    document.getElementById('auditSearch').value = '';
    document.getElementById('auditAuthorFilter').value = '';
    document.getElementById('auditActionFilter').value = '';
    document.getElementById('auditEntityFilter').value = '';
    document.getElementById('auditCountryFilter').value = '';
    document.getElementById('auditDateRangeFilter').value = '';
    filterAuditTable();
}

function populateFilters() {
    // Activity filters
    const activityRows = document.querySelectorAll('#activityTable tbody tr');
    const activityAuthors = new Set();
    const activityActions = new Set();
    const activityProjects = new Set();

    activityRows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length > 5) {
            activityAuthors.add(cells[1].textContent);
            activityActions.add(cells[2].textContent);
            activityProjects.add(cells[5].textContent);
        }
    });

    const activityAuthorSelect = document.getElementById('activityAuthorFilter');
    const activityActionSelect = document.getElementById('activityActionFilter');
    const activityProjectSelect = document.getElementById('activityProjectFilter');

    [...activityAuthors].sort().forEach(a => {
        if (a !== 'N/A') {
            const opt = document.createElement('option');
            opt.value = a;
            opt.textContent = a;
            activityAuthorSelect.appendChild(opt);
        }
    });

    [...activityActions].sort().forEach(a => {
        const opt = document.createElement('option');
        opt.value = a;
        opt.textContent = a;
        activityActionSelect.appendChild(opt);
    });

    [...activityProjects].sort().forEach(p => {
        if (p !== 'N/A') {
            const opt = document.createElement('option');
            opt.value = p;
            opt.textContent = p;
            activityProjectSelect.appendChild(opt);
        }
    });

    // Audit filters
    const auditRows = document.querySelectorAll('#auditTable tbody tr');
    const auditAuthors = new Set();
    const auditActions = new Set();
    const auditEntities = new Set();
    const auditCountries = new Set();

    auditRows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length > 9) {
            auditAuthors.add(cells[1].textContent);
            auditActions.add(cells[3].textContent);
            auditEntities.add(cells[4].textContent);
            auditCountries.add(cells[9].textContent);
        }
    });

    const auditAuthorSelect = document.getElementById('auditAuthorFilter');
    const auditActionSelect = document.getElementById('auditActionFilter');
    const auditEntitySelect = document.getElementById('auditEntityFilter');
    const auditCountrySelect = document.getElementById('auditCountryFilter');

    [...auditAuthors].sort().forEach(a => {
        if (a !== 'N/A') {
            const opt = document.createElement('option');
            opt.value = a;
            opt.textContent = a;
            auditAuthorSelect.appendChild(opt);
        }
    });

    [...auditActions].sort().forEach(a => {
        if (a !== 'N/A') {
            const opt = document.createElement('option');
            opt.value = a;
            opt.textContent = a;
            auditActionSelect.appendChild(opt);
        }
    });

    [...auditEntities].sort().forEach(e => {
        if (e !== 'N/A') {
            const opt = document.createElement('option');
            opt.value = e;
            opt.textContent = e;
            auditEntitySelect.appendChild(opt);
        }
    });

    [...auditCountries].sort().forEach(c => {
        if (c !== 'N/A' && c !== 'Unknown') {
            const opt = document.createElement('option');
            opt.value = c;
            opt.textContent = c;
            auditCountrySelect.appendChild(opt);
        }
    });
}

function isDateValue(val) {
    return /^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}/.test(val);
}

function parseDate(val) {
    const cleaned = val.replace(' UTC', '').replace(' ', 'T') + 'Z';
    return new Date(cleaned).getTime();
}

function sortTable(table, colIndex) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const th = table.querySelectorAll('th')[colIndex];

    const isAsc = th.classList.contains('sort-asc');
    table.querySelectorAll('th').forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
    th.classList.add(isAsc ? 'sort-desc' : 'sort-asc');

    rows.sort((a, b) => {
        let aVal = a.cells[colIndex].textContent.trim();
        let bVal = b.cells[colIndex].textContent.trim();

        // Check if this is a date column
        if (isDateValue(aVal) && isDateValue(bVal)) {
            const aDate = parseDate(aVal);
            const bDate = parseDate(bVal);
            return isAsc ? bDate - aDate : aDate - bDate;
        }

        // Check if numeric
        const aNum = parseFloat(aVal.replace(/[^0-9.-]/g, ''));
        const bNum = parseFloat(bVal.replace(/[^0-9.-]/g, ''));
        if (!isNaN(aNum) && !isNaN(bNum) && aVal.match(/^[\\d.-]+$/)) {
            return isAsc ? bNum - aNum : aNum - bNum;
        }

        return isAsc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
    });

    rows.forEach(row => tbody.appendChild(row));
}

function initResizableColumns(table) {
    const headers = table.querySelectorAll('th');

    headers.forEach(th => {
        const handle = document.createElement('div');
        handle.className = 'resize-handle';
        th.appendChild(handle);

        let startX, startWidth;

        handle.addEventListener('mousedown', (e) => {
            e.stopPropagation();
            startX = e.pageX;
            startWidth = th.offsetWidth;

            const onMouseMove = (e) => {
                const width = startWidth + (e.pageX - startX);
                if (width >= 60) {
                    th.style.width = width + 'px';
                    th.style.minWidth = width + 'px';
                }
            };

            const onMouseUp = () => {
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
            };

            document.addEventListener('mousemove', onMouseMove);
            document.addEventListener('mouseup', onMouseUp);
        });
    });
}

document.addEventListener('DOMContentLoaded', function() {
    populateFilters();

    // Initialize both tables
    ['activityTable', 'auditTable'].forEach(tableId => {
        const table = document.getElementById(tableId);
        table.querySelectorAll('th').forEach((th, index) => {
            th.addEventListener('click', (e) => {
                if (!e.target.classList.contains('resize-handle')) {
                    sortTable(table, index);
                }
            });
        });
        initResizableColumns(table);
    });

    filterActivityTable();
    filterAuditTable();
});
</script>
</body>
</html>
"""

    with open(filename, "w") as f:
        f.write(html)
    print(f"HTML report saved to: {filename}")


def export_to_json(results: dict, filename: str):
    """Export results to JSON file."""
    with open(filename, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"JSON exported to: {filename}")


def export_to_csv(results: dict, filename: str):
    """Export results to CSV file."""
    if not results.get("events"):
        print("No events to export")
        return

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results["events"][0].keys())
        writer.writeheader()
        writer.writerows(results["events"])
    print(f"CSV exported to: {filename}")


def export_to_html(results: dict, filename: str):
    """Export results to interactive HTML report."""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitLab Activity Report</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            color: #292961;
            border-bottom: 3px solid #fc6d26;
            padding-bottom: 10px;
        }
        .summary {
            background-color: #fff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 10px;
        }
        .summary-item {
            text-align: center;
            padding: 10px;
            background: #f9f9f9;
            border-radius: 5px;
        }
        .summary-item .count {
            font-size: 24px;
            font-weight: bold;
            color: #292961;
        }
        .summary-item .label {
            font-size: 12px;
            color: #666;
        }
        .filters {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: center;
            margin-bottom: 15px;
            padding: 15px;
            background: #fff;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
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
        .filter-group input { width: 200px; }
        .filter-group select { min-width: 150px; }
        .btn-clear {
            padding: 8px 16px;
            background-color: #292961;
            color: #fff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            margin-top: 18px;
        }
        .btn-clear:hover { background-color: #3d3d7a; }
        .table-container {
            overflow-x: auto;
            max-height: 70vh;
            overflow-y: auto;
            background: #fff;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            table-layout: auto;
        }
        th {
            background-color: #292961;
            color: #fff;
            padding: 12px 8px;
            text-align: left;
            font-size: 12px;
            cursor: pointer;
            user-select: none;
            position: sticky;
            top: 0;
            z-index: 10;
            min-width: 60px;
            overflow: hidden;
        }
        .resize-handle {
            position: absolute;
            right: 0;
            top: 0;
            bottom: 0;
            width: 5px;
            cursor: col-resize;
            background: transparent;
        }
        .resize-handle:hover {
            background: rgba(252, 109, 38, 0.5);
        }
        th:hover { background-color: #3d3d7a; }
        th .sort-icon { margin-left: 5px; font-size: 10px; }
        th.sort-asc .sort-icon::after { content: ' ▲'; }
        th.sort-desc .sort-icon::after { content: ' ▼'; }
        th:not(.sort-asc):not(.sort-desc) .sort-icon::after { content: ' ⇅'; opacity: 0.5; }
        td {
            padding: 10px 8px;
            border-bottom: 1px solid #ddd;
            font-size: 12px;
            white-space: normal;
            word-wrap: break-word;
            max-width: 300px;
            vertical-align: top;
        }
        tr:hover { background-color: #f9f9f9; }
        tr.hidden { display: none; }
        .action-pushed, .action-merged { color: #1aaa55; font-weight: bold; }
        .action-created, .action-opened { color: #1f78d1; font-weight: bold; }
        .action-closed, .action-destroyed { color: #db3b21; font-weight: bold; }
        .action-commented { color: #fc6d26; font-weight: bold; }
        td a { color: #1f78d1; text-decoration: none; }
        td a:hover { text-decoration: underline; }
        .timestamp { color: #879596; font-size: 12px; margin-bottom: 20px; }
        .result-count { color: #666; font-size: 13px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <h1>GitLab Activity Report</h1>
    <p class="timestamp">Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>

    <div class="summary">
        <strong>Summary</strong>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="count">""" + (str(results["scan_info"]["projects_scanned"]) if results["scan_info"]["projects_scanned"] > 0 else str(results["scan_info"]["users_scanned"])) + """</div>
                <div class="label">""" + ("Projects Scanned" if results["scan_info"]["projects_scanned"] > 0 else "Users Scanned") + """</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(results["scan_info"]["total_events"]) + """</div>
                <div class="label">Total Events</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(set(e["Action"] for e in results.get("events", [])))) + """</div>
                <div class="label">Action Types</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(set(e["ProjectName"] for e in results.get("events", []) if e["ProjectName"] != "N/A"))) + """</div>
                <div class="label">Projects</div>
            </div>
        </div>
        <div style="margin-top: 10px; font-size: 12px; color: #666;">
            <strong>Date Range:</strong> """ + results["scan_info"]["filters"]["after"] + """ to """ + (results["scan_info"]["filters"]["before"] if results["scan_info"]["filters"]["before"] != "N/A" else "now") + """
        </div>
    </div>

    <div class="filters">
        <div class="filter-group">
            <label>Search</label>
            <input type="text" id="searchInput" placeholder="Search all columns..." onkeyup="filterTable()">
        </div>
        <div class="filter-group">
            <label>Author</label>
            <select id="authorFilter" onchange="filterTable()">
                <option value="">All Authors</option>
            </select>
        </div>
        <div class="filter-group">
            <label>Action</label>
            <select id="actionFilter" onchange="filterTable()">
                <option value="">All Actions</option>
            </select>
        </div>
        <div class="filter-group">
            <label>Target Type</label>
            <select id="targetFilter" onchange="filterTable()">
                <option value="">All Types</option>
            </select>
        </div>
        <div class="filter-group">
            <label>Project</label>
            <select id="projectFilter" onchange="filterTable()">
                <option value="">All Projects</option>
            </select>
        </div>
        <div class="filter-group">
            <label>Date Range</label>
            <select id="dateRangeFilter" onchange="filterTable()">
                <option value="">All Time</option>
                <option value="1">Last 1 Day</option>
                <option value="3">Last 3 Days</option>
                <option value="7">Last 7 Days</option>
                <option value="30">Last 30 Days</option>
                <option value="90">Last 90 Days</option>
            </select>
        </div>
        <button class="btn-clear" onclick="clearFilters()">Clear Filters</button>
    </div>

    <div class="result-count">Showing <span id="visibleCount">0</span> of """ + str(len(results.get("events", []))) + """ events</div>

    <div class="table-container">
        <table id="eventsTable">
            <thead>
                <tr>
                    <th>Event ID<span class="sort-icon"></span></th>
                    <th>Author<span class="sort-icon"></span></th>
                    <th>Action<span class="sort-icon"></span></th>
                    <th>Target Type<span class="sort-icon"></span></th>
                    <th>Target Title<span class="sort-icon"></span></th>
                    <th>Project<span class="sort-icon"></span></th>
                    <th>Ref<span class="sort-icon"></span></th>
                    <th>Created At<span class="sort-icon"></span></th>
                </tr>
            </thead>
            <tbody>
"""

    for event in results.get("events", []):
        action = event["Action"]
        action_class = ""
        if "push" in action.lower():
            action_class = "action-pushed"
        elif "merge" in action.lower():
            action_class = "action-merged"
        elif "create" in action.lower() or "open" in action.lower():
            action_class = "action-created"
        elif "close" in action.lower() or "destroy" in action.lower():
            action_class = "action-closed"
        elif "comment" in action.lower():
            action_class = "action-commented"

        # Build project link
        project_name = event['ProjectName']
        project_url = event['ProjectUrl']
        if project_url and project_url != "N/A":
            project_cell = f'<a href="{project_url}" target="_blank">{project_name}</a>'
        else:
            project_cell = project_name

        # Build ref link
        ref = event['Ref']
        ref_url = event['RefUrl']
        if ref_url and ref_url != "N/A":
            ref_cell = f'<a href="{ref_url}" target="_blank">{ref}</a>'
        else:
            ref_cell = ref

        html += f"""                <tr>
                    <td>{event['EventId']}</td>
                    <td>{event['AuthorUsername']}</td>
                    <td class="{action_class}">{event['Action']}</td>
                    <td>{event['TargetType']}</td>
                    <td>{event['TargetTitle']}</td>
                    <td>{project_cell}</td>
                    <td>{ref_cell}</td>
                    <td>{event['CreatedAt']}</td>
                </tr>
"""

    html += """            </tbody>
        </table>
    </div>

<script>
function filterTable() {
    const search = document.getElementById('searchInput').value.toLowerCase();
    const author = document.getElementById('authorFilter').value;
    const action = document.getElementById('actionFilter').value;
    const target = document.getElementById('targetFilter').value;
    const project = document.getElementById('projectFilter').value;
    const dateRange = document.getElementById('dateRangeFilter').value;

    const table = document.getElementById('eventsTable');
    const rows = table.querySelectorAll('tbody tr');
    let visibleCount = 0;

    const now = new Date();
    const cutoffDate = dateRange ? new Date(now.getTime() - (parseInt(dateRange) * 24 * 60 * 60 * 1000)) : null;

    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        const text = Array.from(cells).map(c => c.textContent.toLowerCase()).join(' ');
        const rowAuthor = cells[1].textContent;
        const rowAction = cells[2].textContent;
        const rowTarget = cells[3].textContent;
        const rowProject = cells[5].textContent;
        const rowDate = cells[7].textContent;

        let show = text.includes(search);
        if (author && rowAuthor !== author) show = false;
        if (action && rowAction !== action) show = false;
        if (target && rowTarget !== target) show = false;
        if (project && rowProject !== project) show = false;

        if (cutoffDate && rowDate) {
            const cleaned = rowDate.replace(' UTC', '').replace(' ', 'T') + 'Z';
            const eventDate = new Date(cleaned);
            if (eventDate < cutoffDate) show = false;
        }

        row.classList.toggle('hidden', !show);
        if (show) visibleCount++;
    });

    document.getElementById('visibleCount').textContent = visibleCount;
}

function clearFilters() {
    document.getElementById('searchInput').value = '';
    document.getElementById('authorFilter').value = '';
    document.getElementById('actionFilter').value = '';
    document.getElementById('targetFilter').value = '';
    document.getElementById('projectFilter').value = '';
    document.getElementById('dateRangeFilter').value = '';
    filterTable();
}

function populateFilters() {
    const table = document.getElementById('eventsTable');
    const rows = table.querySelectorAll('tbody tr');
    const authors = new Set();
    const actions = new Set();
    const targets = new Set();
    const projects = new Set();

    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length > 5) {
            authors.add(cells[1].textContent);
            actions.add(cells[2].textContent);
            targets.add(cells[3].textContent);
            projects.add(cells[5].textContent);
        }
    });

    const authorSelect = document.getElementById('authorFilter');
    const actionSelect = document.getElementById('actionFilter');
    const targetSelect = document.getElementById('targetFilter');
    const projectSelect = document.getElementById('projectFilter');

    [...authors].sort().forEach(a => {
        const opt = document.createElement('option');
        opt.value = a;
        opt.textContent = a;
        authorSelect.appendChild(opt);
    });

    [...actions].sort().forEach(a => {
        const opt = document.createElement('option');
        opt.value = a;
        opt.textContent = a;
        actionSelect.appendChild(opt);
    });

    [...targets].sort().forEach(t => {
        if (t !== 'N/A') {
            const opt = document.createElement('option');
            opt.value = t;
            opt.textContent = t;
            targetSelect.appendChild(opt);
        }
    });

    [...projects].sort().forEach(p => {
        if (p !== 'N/A') {
            const opt = document.createElement('option');
            opt.value = p;
            opt.textContent = p;
            projectSelect.appendChild(opt);
        }
    });
}

function isDateValue(val) {
    return /^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}/.test(val);
}

function parseDate(val) {
    const cleaned = val.replace(' UTC', '').replace(' ', 'T') + 'Z';
    return new Date(cleaned).getTime();
}

function sortTable(colIndex) {
    const table = document.getElementById('eventsTable');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const th = table.querySelectorAll('th')[colIndex];

    const isAsc = th.classList.contains('sort-asc');
    table.querySelectorAll('th').forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
    th.classList.add(isAsc ? 'sort-desc' : 'sort-asc');

    rows.sort((a, b) => {
        let aVal = a.cells[colIndex].textContent.trim();
        let bVal = b.cells[colIndex].textContent.trim();

        // Check if this is a date column
        if (isDateValue(aVal) && isDateValue(bVal)) {
            const aDate = parseDate(aVal);
            const bDate = parseDate(bVal);
            return isAsc ? bDate - aDate : aDate - bDate;
        }

        // Check if numeric
        const aNum = parseFloat(aVal.replace(/[^0-9.-]/g, ''));
        const bNum = parseFloat(bVal.replace(/[^0-9.-]/g, ''));
        if (!isNaN(aNum) && !isNaN(bNum) && aVal.match(/^[\\d.-]+$/)) {
            return isAsc ? bNum - aNum : aNum - bNum;
        }

        return isAsc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
    });

    rows.forEach(row => tbody.appendChild(row));
}

// Column resize functionality
function initResizableColumns() {
    const table = document.getElementById('eventsTable');
    const headers = table.querySelectorAll('th');

    headers.forEach(th => {
        const handle = document.createElement('div');
        handle.className = 'resize-handle';
        th.appendChild(handle);

        let startX, startWidth;

        handle.addEventListener('mousedown', (e) => {
            e.stopPropagation();
            startX = e.pageX;
            startWidth = th.offsetWidth;

            const onMouseMove = (e) => {
                const width = startWidth + (e.pageX - startX);
                if (width >= 60) {
                    th.style.width = width + 'px';
                    th.style.minWidth = width + 'px';
                }
            };

            const onMouseUp = () => {
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
            };

            document.addEventListener('mousemove', onMouseMove);
            document.addEventListener('mouseup', onMouseUp);
        });
    });
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    populateFilters();

    // Add click handlers for sorting
    const table = document.getElementById('eventsTable');
    table.querySelectorAll('th').forEach((th, index) => {
        th.addEventListener('click', (e) => {
            if (!e.target.classList.contains('resize-handle')) {
                sortTable(index);
            }
        });
    });

    // Initialize resizable columns
    initResizableColumns();

    // Initial filter
    filterTable();
});
</script>
</body>
</html>
"""

    with open(filename, "w") as f:
        f.write(html)
    print(f"HTML report saved to: {filename}")


def print_report(results: dict):
    """Print summary report to console."""
    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    if results['scan_info'].get('groups_scanned', 0) > 0:
        print(f"Groups scanned: {results['scan_info']['groups_scanned']}")
    elif results['scan_info'].get('projects_scanned', 0) > 0:
        print(f"Projects scanned: {results['scan_info']['projects_scanned']}")
    else:
        print(f"Users scanned: {results['scan_info']['users_scanned']}")
    print(f"Total events: {results['scan_info']['total_events']}")
    print(f"Scan time: {results['scan_info']['scan_time']}")
    print()
    print("Filters applied:")
    for key, value in results["scan_info"]["filters"].items():
        print(f"  {key}: {value}")

    if results.get("events"):
        # Count by action
        action_counts = {}
        for event in results["events"]:
            action = event["Action"]
            action_counts[action] = action_counts.get(action, 0) + 1

        print()
        print("Events by action:")
        for action, count in sorted(action_counts.items(), key=lambda x: -x[1]):
            print(f"  {action}: {count}")


def main():
    parser = argparse.ArgumentParser(
        description="Scan GitLab user activities using the Events API"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output"
    )
    parser.add_argument(
        "-o", "--output",
        help="Export to JSON file"
    )
    parser.add_argument(
        "--csv",
        help="Export to CSV file"
    )
    parser.add_argument(
        "--html",
        help="Export to HTML file"
    )
    parser.add_argument(
        "--token",
        help="GitLab access token (or set GITLAB_TOKEN env var)"
    )
    parser.add_argument(
        "--users",
        help="Comma-separated list of usernames to scan (default: authenticated user)"
    )
    parser.add_argument(
        "--projects",
        help="Comma-separated list of project paths to scan (e.g., group/project)"
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Scan audit events (sign-ins, security events) instead of activity events"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        dest="scan_all",
        help="Scan both activity and audit events (creates tabbed HTML report)"
    )
    parser.add_argument(
        "--groups",
        help="Comma-separated list of group paths for audit events (e.g., my-group)"
    )
    parser.add_argument(
        "--action",
        choices=ACTION_TYPES,
        help="Filter by action type"
    )
    parser.add_argument(
        "--target-type",
        choices=TARGET_TYPES,
        help="Filter by target type"
    )
    parser.add_argument(
        "--before",
        help="Filter events before date (YYYY-MM-DD)"
    )
    parser.add_argument(
        "--after",
        help="Filter events after date (YYYY-MM-DD)"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=90,
        help="Filter events from last N days (default: 90)"
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=100,
        help="Maximum pages to fetch per user (default: 100)"
    )

    args = parser.parse_args()

    # Get access token
    access_token = args.token or os.getenv("GITLAB_TOKEN")
    if not access_token:
        print("Error: GitLab access token required.")
        print("Set GITLAB_TOKEN environment variable or use --token flag")
        sys.exit(1)

    # Parse usernames
    usernames = None
    if args.users:
        usernames = [u.strip() for u in args.users.split(",")]

    # Parse project paths
    project_paths = None
    if args.projects:
        project_paths = [p.strip() for p in args.projects.split(",")]

    # Parse group paths
    group_paths = None
    if args.groups:
        group_paths = [g.strip() for g in args.groups.split(",")]

    print("GitLab Activity Scanner")
    print("=" * 60)

    if args.scan_all:
        # Scan both activity and audit events
        print("Mode: All Events (Activity + Audit)")
        print()

        # Scan activity events
        print("--- Scanning Activity Events ---")
        activity_results = scan_activities(
            access_token=access_token,
            usernames=usernames,
            project_paths=project_paths,
            action=args.action,
            target_type=args.target_type,
            before=args.before,
            after=args.after,
            days=args.days,
            max_pages=args.max_pages,
            verbose=args.verbose
        )

        print()
        print("--- Scanning Audit Events ---")
        audit_results = scan_audit_events(
            access_token=access_token,
            usernames=usernames,
            group_paths=group_paths,
            project_paths=project_paths,
            before=args.before,
            after=args.after,
            days=args.days,
            max_pages=args.max_pages,
            verbose=args.verbose
        )

        # Print combined summary
        print("\n" + "=" * 60)
        print("SCAN COMPLETE")
        print("=" * 60)
        print(f"Activity events: {len(activity_results.get('events', []))}")
        print(f"Audit events: {len(audit_results.get('events', []))}")
        print(f"Total events: {len(activity_results.get('events', [])) + len(audit_results.get('events', []))}")

        # Export results
        if args.output:
            combined = {
                "activity_events": activity_results,
                "audit_events": audit_results
            }
            export_to_json(combined, args.output)

        if args.html:
            export_combined_to_html(activity_results, audit_results, args.html)

        if args.csv:
            print("Note: CSV export not supported for combined mode. Use --audit or no flag for CSV.")

    elif args.audit:
        # Scan audit events only
        print("Mode: Audit Events")
        results = scan_audit_events(
            access_token=access_token,
            usernames=usernames,
            group_paths=group_paths,
            project_paths=project_paths,
            before=args.before,
            after=args.after,
            days=args.days,
            max_pages=args.max_pages,
            verbose=args.verbose
        )

        # Print summary
        print_report(results)

        # Export results
        if args.output:
            export_to_json(results, args.output)

        if args.csv:
            export_to_csv(results, args.csv)

        if args.html:
            export_audit_to_html(results, args.html)

    else:
        # Scan activity events only
        results = scan_activities(
            access_token=access_token,
            usernames=usernames,
            project_paths=project_paths,
            action=args.action,
            target_type=args.target_type,
            before=args.before,
            after=args.after,
            days=args.days,
            max_pages=args.max_pages,
            verbose=args.verbose
        )

        # Print summary
        print_report(results)

        # Export results
        if args.output:
            export_to_json(results, args.output)

        if args.csv:
            export_to_csv(results, args.csv)

        if args.html:
            export_to_html(results, args.html)


if __name__ == "__main__":
    main()
