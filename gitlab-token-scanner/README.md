# GitLab Token Scanner

A Python script to scan all active group access tokens, project access tokens, and deploy tokens in GitLab Cloud, showing who created the token and when.

## Features

- Scan all groups for access tokens and deploy tokens
- Scan all projects for access tokens and deploy tokens
- View token status (active/expired/revoked)
- See who created the token and when
- See token expiration dates
- Filter for active-only tokens
- Export results to JSON

## Prerequisites

- Python 3.8 or higher
- A GitLab Personal Access Token with appropriate permissions

## GitLab Token Setup

1. Go to [GitLab Personal Access Tokens](https://gitlab.com/-/user_settings/personal_access_tokens)

2. Create a new token with the following settings:
   - **Token name**: `Token Scanner` (or any name you prefer)
   - **Expiration date**: Set as appropriate for your needs
   - **Scopes**: Select the following:
     - `api` (Full API access) - Required to read access tokens
     - `read_api` (Read API access) - Alternative if you want read-only access

3. Copy the token value immediately (it won't be shown again)

## Required Permissions

To scan tokens, you need sufficient permissions:

- **Group Access Tokens**: You must be an Owner or Maintainer of the group
- **Project Access Tokens**: You must be a Maintainer of the project
- **Deploy Tokens**: You must be a Maintainer of the project/group

If you don't have permission for a resource, that resource will be skipped silently.

## Installation

1. Navigate to the project directory:
   ```bash
   cd gitlab-token-scanner
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
   Use `deactivate` to exit from virtual environment.

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

5. Configure credentials:
   ```bash
   cp .env.example .env
   ```

   Edit `.env` and fill in your GitLab token:
   ```
   GITLAB_ACCESS_TOKEN=your-gitlab-token-here
   ```

## Usage

### Basic Scan (All Tokens)

```bash
python scan_tokens.py
```

### Verbose Output (Show All Details)

```bash
python scan_tokens.py -v
```

### Active Tokens Only

```bash
python scan_tokens.py --active-only
```

### Scan Groups Only

```bash
python scan_tokens.py --groups-only
```

### Scan Projects Only

```bash
python scan_tokens.py --projects-only
```

### Skip Deploy Tokens

```bash
python scan_tokens.py --skip-deploy-tokens
```

### Scan Specific Group or Project

```bash
# Scan specific group
python scan_tokens.py --group-id 12345

# Scan specific project
python scan_tokens.py --project-id 67890
```

### Export Results to JSON

```bash
python scan_tokens.py -o results.json
```

### Combine Options

```bash
python scan_tokens.py --active-only -v -o results.json
```

## Output

Example output:
```
Fetching groups...
Found 5 group(s) to scan.
[1/5] Scanning group: my-organization/my-group

------------------------------------------------------------
Token Type: Group Access Token
Group: my-organization/my-group
Name: CI/CD Token
Status: ACTIVE
Created At: 2024-06-15T10:30:00Z
Expires At: 2025-06-15T10:30:00Z
Created By: john.doe

Fetching projects...
Found 10 project(s) to scan.
[1/10] Scanning project: my-organization/my-project

------------------------------------------------------------
Token Type: Project Access Token
Project: my-organization/my-project
Name: Deploy Bot
Status: ACTIVE
Created At: 2024-08-20T14:45:00Z
Expires At: Never
Created By: jane.smith

============================================================
SUMMARY
============================================================
Total tokens found: 15
Active tokens: 12

Group Access Tokens: 5 (Active: 4)
Group Deploy Tokens: 2 (Active: 2)
Project Access Tokens: 6 (Active: 5)
Project Deploy Tokens: 2 (Active: 1)

============================================================
ACTIVE TOKENS BY EXPIRATION
============================================================
  - [Project Access Token] Deploy Bot (my-org/project) - Expires: 2025-01-15 (30 days)
  - [Group Access Token] CI/CD Token (my-org/group) - Expires: 2025-06-15 (180 days)
  - [Deploy Token] Registry Access (my-org/project) - Expires: Never
```

## JSON Output Format

When using `-o results.json`, the output includes:

```json
{
  "timestamp": "2024-12-17T10:30:00.000000",
  "summary": {
    "group_access_tokens": {"total": 5, "active": 4},
    "project_access_tokens": {"total": 6, "active": 5},
    "group_deploy_tokens": {"total": 2, "active": 2},
    "project_deploy_tokens": {"total": 2, "active": 1}
  },
  "tokens": [
    {
      "token_type": "Group Access Token",
      "parent_type": "Group",
      "parent_name": "my-organization/my-group",
      "id": 12345,
      "name": "CI/CD Token",
      "created_at": "2024-06-15T10:30:00Z",
      "expires_at": "2025-06-15T10:30:00Z",
      "created_by": "john.doe",
      "active": true,
      "revoked": false,
      "is_expired": false,
      "scopes": ["api", "read_repository"],
      "access_level": 40
    }
  ]
}
```

## Troubleshooting

### "Unauthorized" Error
- Verify your `GITLAB_ACCESS_TOKEN` is correct
- Check that the token hasn't expired
- Ensure the token has `api` or `read_api` scope

### No Tokens Found
- You may not have sufficient permissions (Owner/Maintainer) for the groups/projects
- The groups/projects may not have any access tokens or deploy tokens created

### Some Groups/Projects Skipped
- This is normal if you don't have Maintainer/Owner permissions
- The script silently skips resources where you lack permissions

### Token Creator Shows "N/A"
- The `created_by` field may not be available for older tokens
- Some GitLab versions may not expose this information

## Security Notes

- Never commit your `.env` file to version control
- The `.env` file is excluded in `.gitignore` by default
- Rotate your GitLab access token periodically
- Use the minimum required scopes for your token
- Consider using a dedicated service account for scanning
