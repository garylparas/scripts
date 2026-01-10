# GitLab Activity Scanner

Python script to scan GitLab user and project activities (events) using the GitLab Events API and Audit Events API.

## Features

- Scan activities for authenticated user or specific users
- Scan activities for specific projects
- **Scan audit events** (sign-ins, security events) for users or groups
- **Combined scan** with tabbed HTML report for both activity and audit events
- Filter by action type (pushed, merged, created, closed, etc.)
- Filter by target type (issue, merge_request, project, etc.)
- Filter by date range (before, after, or last N days)
- Export results to CSV, HTML, or JSON
- **Interactive HTML reports** with filtering, sorting, and resizable columns

## Prerequisites

- Python 3.8 or higher
- GitLab access token with appropriate scope:
  - `read_user` - Sufficient for activity events only
  - `api` - Required for audit events

## Installation

1. Navigate to the project directory:
   ```bash
   cd gitlab-activity-scanner
   ```

2. Create a virtual environment:
   ```bash
   python3 -m venv venv
   ```

3. Activate the virtual environment:
   ```bash
   # Linux/macOS
   source venv/bin/activate

   # Windows
   venv\Scripts\activate
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

5. Set up your GitLab token:
   ```bash
   cp .env.example .env
   # Edit .env and add your GitLab token
   ```

## Usage

```bash
# Basic scan (authenticated user, all events)
python scan_activities.py

# Scan with verbose output
python scan_activities.py -v

# Export to HTML/CSV/JSON
python scan_activities.py --html activities.html --csv activities.csv -o activities.json

# Scan specific users
python scan_activities.py --users john.doe,jane.smith

# Scan specific projects
python scan_activities.py --projects group/project-name
python scan_activities.py --projects group/project1,group/project2

# Filter by action type
python scan_activities.py --action pushed
python scan_activities.py --action merged
python scan_activities.py --action "commented on"

# Filter by target type
python scan_activities.py --target-type merge_request
python scan_activities.py --target-type issue

# Filter by date range
python scan_activities.py --after 2024-01-01 --before 2024-12-31
python scan_activities.py --days 30  # Last 30 days

# Combine filters
python scan_activities.py --users john.doe --action pushed --days 7 --html report.html
python scan_activities.py --projects group/project --action merged --days 30 --html report.html

# Scan audit events for groups (requires group owner access)
python scan_activities.py --audit --groups my-group --days 30 --html audit.html
python scan_activities.py --audit --groups my-group --users john.doe --days 7 --html audit.html

# Scan audit events for projects (requires maintainer access)
python scan_activities.py --audit --projects group/project --days 30 --html audit.html

# Scan both activity and audit events (tabbed HTML report)
python scan_activities.py --all --groups my-group --days 30 --html combined.html
python scan_activities.py --all --projects group/project --days 30 --html combined.html
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Show detailed output |
| `-o, --output FILE` | Export to JSON file |
| `--csv FILE` | Export to CSV file |
| `--html FILE` | Export to HTML file |
| `--token TOKEN` | GitLab access token (or set GITLAB_TOKEN env var) |
| `--users USERS` | Comma-separated list of usernames to scan |
| `--projects PROJECTS` | Comma-separated list of project paths to scan (e.g., group/project) |
| `--audit` | Scan audit events (sign-ins, security events) instead of activity events |
| `--all` | Scan both activity and audit events (creates tabbed HTML report) |
| `--groups GROUPS` | Comma-separated list of group paths for audit events (e.g., my-group) |
| `--action ACTION` | Filter by action type (activity events only) |
| `--target-type TYPE` | Filter by target type (activity events only) |
| `--before DATE` | Filter events before date (YYYY-MM-DD) |
| `--after DATE` | Filter events after date (YYYY-MM-DD) |
| `--days N` | Filter events from last N days (default: 90) |
| `--max-pages N` | Maximum pages to fetch per user/project (default: 100) |

## Action Types

| Action | Description |
|--------|-------------|
| `approved` | Approved a merge request |
| `closed` | Closed an issue or merge request |
| `commented on` | Added a comment |
| `created` | Created a resource |
| `destroyed` | Deleted a resource |
| `expired` | Resource expired |
| `joined` | Joined a project or group |
| `left` | Left a project or group |
| `merged` | Merged a merge request |
| `pushed` | Pushed commits |
| `pushed new` | Pushed a new branch |
| `pushed to` | Pushed to a branch |
| `reopened` | Reopened an issue or merge request |
| `updated` | Updated a resource |

## Target Types

| Target | Description |
|--------|-------------|
| `epic` | Epic (group-level) |
| `issue` | Issue |
| `merge_request` | Merge request |
| `milestone` | Milestone |
| `note` | Comment/Note |
| `project` | Project |
| `snippet` | Code snippet |
| `user` | User |

## Output Columns

| Column | Description |
|--------|-------------|
| EventId | Unique event identifier |
| AuthorUsername | Username of the user who performed the action |
| AuthorName | Display name of the author |
| Action | Action performed (pushed, merged, created, etc.) |
| TargetType | Type of target (issue, merge_request, etc.) |
| TargetTitle | Title of the target resource |
| TargetId | ID of the target resource |
| ProjectName | Project path (e.g., group/project) - clickable link in HTML |
| ProjectUrl | Full URL to the project repository |
| RefType | Reference type for push events (branch, tag) |
| Ref | Reference name, MR (!123), issue (#123), or branch/tag - clickable link in HTML |
| RefUrl | Full URL to the branch/tag/MR/issue |
| NotePreview | Preview of comment (for note events) |
| CreatedAt | Timestamp of the event (UTC) |

## Audit Events

Audit events track sign-ins, security changes, and administrative actions. Use the `--audit` flag to scan audit events instead of activity events.

**Note:** Audit events require `--groups` or `--projects` to be specified (instance-level audit events are not available on GitLab cloud).

### Requirements

- **Group-level audit events**: Requires group owner access (Developers/Maintainers only see their own actions)
- **Project-level audit events**: Requires maintainer access (Developers only see their own actions)
- Token must have `api` scope

### Audit Event Columns

| Column | Description |
|--------|-------------|
| EventId | Unique audit event identifier |
| AuthorId | ID of the user who performed the action |
| AuthorUsername | Username of the user (from registration_details) |
| AuthorName | Display name of the user |
| AuthorEmail | Email address of the user |
| Action | Action performed (event_name, e.g., authenticated_with_group_saml) |
| EntityType | Type of entity (User, Group, Project, etc.) |
| EntityPath | Path to the entity |
| TargetType | Type of target resource |
| TargetDetails | Details about the target |
| IPAddress | IP address of the request |
| Country | Country of the IP address (via ip-api.com batch geolocation) |
| CustomMessage | Additional message (if any) |
| CreatedAt | Timestamp of the event (UTC) |

### Common Audit Actions

| Action | Description |
|--------|-------------|
| `authenticated_with_group_saml` | User signed in with Group SAML |
| `user_logged_in` | User signed in |
| `user_logged_out` | User signed out |
| `user_access_locked` | User account locked |
| `key_added` | SSH key added |
| `key_removed` | SSH key removed |
| `two_factor_enabled` | 2FA enabled |
| `two_factor_disabled` | 2FA disabled |
| `password_changed` | Password changed |
| `user_created` | New user created |
| `user_removed` | User removed |

## HTML Report Features

- **Sortable columns** - Click column headers to sort
- **Resizable columns** - Drag column edges to resize
- **Sticky headers** - Headers stay visible when scrolling
- **Tabbed interface** - Combined reports (`--all`) show Activity Events and Audit Events in separate tabs
- **Date range display** - Shows the scanned date range in the summary
- **Filters:**
  - Search (all columns)
  - Author dropdown
  - Action dropdown
  - Target type / Entity type dropdown
  - Project dropdown (activity events only)
  - Country dropdown (audit events only)

## Console Output Examples

### User Activity Scan

```
GitLab Activity Scanner
============================================================
[1/1] Scanning activities for: john.doe
Fetching info for 12 projects...

============================================================
SCAN COMPLETE
============================================================
Users scanned: 1
Total events: 156
Scan time: 2024-01-15 10:30:00

Filters applied:
  action: all
  target_type: all
  before: N/A
  after: 2024-01-01

Events by action:
  pushed to: 78
  commented on: 45
  created: 15
  merged: 12
  closed: 6
```

### Project Activity Scan

```
GitLab Activity Scanner
============================================================
[1/2] Scanning activities for project: group/project-one
[2/2] Scanning activities for project: group/project-two
Fetching info for 2 projects...

============================================================
SCAN COMPLETE
============================================================
Projects scanned: 2
Total events: 324
Scan time: 2024-01-15 10:35:00

Filters applied:
  action: all
  target_type: all
  before: N/A
  after: 2024-01-01

Events by action:
  pushed to: 145
  commented on: 89
  merged: 45
  created: 30
  closed: 15
```

### Audit Event Scan

```
GitLab Activity Scanner
============================================================
Mode: Audit Events
[1/1] Scanning audit events for group: my-group
Looking up countries for 15 unique IP addresses...

============================================================
SCAN COMPLETE
============================================================
Groups scanned: 1
Total events: 42
Scan time: 2024-01-15 10:40:00

Filters applied:
  before: N/A
  after: 2024-01-01

Events by action:
  authenticated_with_group_saml: 28
  key_added: 5
  password_changed: 4
  two_factor_enabled: 3
  user_logged_out: 2
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITLAB_TOKEN` | GitLab access token (required) |
| `GITLAB_API_URL` | GitLab API URL (default: https://gitlab.com/api/v4) |

## GitLab Token Scopes

The access token requires one of the following scopes depending on usage:

| Scope | Activity Events | Audit Events |
|-------|-----------------|--------------|
| `read_user` | Yes | No |
| `api` | Yes | Yes |

To create a token:
1. Go to GitLab → User Settings → Access Tokens
2. Create a new token with the appropriate scope
3. Copy the token and add it to your `.env` file

**Note:** Use `api` scope if you need to scan audit events.

## Security Notes

- Never commit your `.env` file or access token
- The `.gitignore` excludes output files (*.csv, *.html, *.json) by default
- Token is read from environment variable or command line argument

## API Reference

This script uses the following GitLab APIs:
- [GitLab Events API Documentation](https://docs.gitlab.com/api/events/)
- [GitLab Audit Events API Documentation](https://docs.gitlab.com/api/audit_events/)
