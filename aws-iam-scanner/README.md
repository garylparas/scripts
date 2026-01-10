# AWS IAM Scanner

Python scripts to scan IAM users, access keys, and groups across multiple AWS accounts using AWS CLI profiles.

## Scripts

| Script | Description |
|--------|-------------|
| `scan_iam_users.py` | Scan IAM users and their access keys |
| `scan_iam_groups.py` | Scan IAM groups and their members |

## Features

- Scan across multiple AWS accounts using profile patterns
- Export results to CSV, HTML, or JSON
- **Interactive HTML reports** with sorting and filtering
- Account names extracted from AWS SSO config
- Graceful handling of expired SSO credentials
- Dynamic summary that updates with filters

## Prerequisites

- Python 3.8 or higher
- AWS CLI configured with SSO profiles
- Appropriate IAM permissions

## Required IAM Permissions

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity",
                "iam:ListUsers",
                "iam:GetLoginProfile",
                "iam:ListAccessKeys",
                "iam:GetAccessKeyLastUsed",
                "iam:ListGroups",
                "iam:GetGroup",
                "iam:ListGroupPolicies",
                "iam:ListAttachedGroupPolicies"
            ],
            "Resource": "*"
        }
    ]
}
```

These permissions are included in `ReadOnlyAccess` or `AdministratorAccess` managed policies.

## Installation

1. Navigate to the project directory:
   ```bash
   cd aws-iam-scanner
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

5. Ensure AWS SSO is configured and logged in:
   ```bash
   aws sso login
   ```

---

## IAM Users Scanner (`scan_iam_users.py`)

Scans all IAM users and their access keys across multiple AWS accounts.

### Usage

```bash
# Basic scan (all admin profiles)
python scan_iam_users.py

# Verbose output
python scan_iam_users.py -v

# Export to CSV/HTML/JSON
python scan_iam_users.py --csv users.csv --html users.html -o users.json

# Scan single profile
python scan_iam_users.py --profile prod-platform.admin

# Use different profile pattern
python scan_iam_users.py --profile-pattern ".readonly"

# Exclude BedrockAPIKey users
python scan_iam_users.py --exclude-bedrock
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Show detailed output |
| `-o, --output FILE` | Export to JSON file |
| `--csv FILE` | Export to CSV file |
| `--html FILE` | Export to HTML file |
| `--profile PROFILE` | Scan specific profile |
| `--profile-pattern PATTERN` | Profile pattern (default: `.admin`) |
| `--exclude-bedrock` | Exclude 'BedrockAPIKey-*' users |

### Output Columns

| Column | Description |
|--------|-------------|
| AccountId | AWS Account ID |
| AccountName | AWS Account Name (from SSO config) |
| Username | IAM username |
| ConsoleAccess | TRUE/Yes if console login enabled |
| AccessKeyId | Access key ID (or N/A) |
| Status | Active or Inactive |
| CreateDate | Key creation date |
| AgeDays | Key age in days |
| LastUsedDate | When key was last used |
| LastUsedDays | Days since key was last used |
| LastUsedService | AWS service where key was used |
| UserCreateDate | User creation date |
| UserCreateDays | User age in days |

### HTML Filters

- Search (all columns)
- Account dropdown
- Console Access (Yes/No)
- Key Status (Active/Inactive/No Key)
- Key Age (Over 90/180/365 days)
- Last Used (Over 30/90/180/365 days)

---

## IAM Groups Scanner (`scan_iam_groups.py`)

Scans all IAM groups and their members across multiple AWS accounts.

### Usage

```bash
# Basic scan (all admin profiles)
python scan_iam_groups.py

# Verbose output
python scan_iam_groups.py -v

# Export to CSV/HTML/JSON
python scan_iam_groups.py --csv groups.csv --html groups.html -o groups.json

# Scan single profile
python scan_iam_groups.py --profile prod-platform.admin

# Use different profile pattern
python scan_iam_groups.py --profile-pattern ".readonly"
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Show detailed output |
| `-o, --output FILE` | Export to JSON file |
| `--csv FILE` | Export to CSV file |
| `--html FILE` | Export to HTML file |
| `--profile PROFILE` | Scan specific profile |
| `--profile-pattern PATTERN` | Profile pattern (default: `.admin`) |

### Output Columns

| Column | Description |
|--------|-------------|
| AccountId | AWS Account ID |
| AccountName | AWS Account Name (from SSO config) |
| GroupName | IAM group name |
| GroupId | Unique group ID |
| CreateDate | Group creation date |
| AgeDays | Group age in days |
| MemberCount | Number of users in group |
| Members | List of usernames |
| TotalPolicies | Total attached policies |
| InlinePolicyCount | Number of inline policies |
| ManagedPolicyCount | Number of managed policies |
| InlinePolicies | List of inline policy names |
| ManagedPolicies | List of managed policy names |

### HTML Filters

- Search (all columns)
- Account dropdown
- Members (Empty/Has members)
- Policies (No policies/Has policies)
- Group Age (Over 90/180/365 days)

---

## Console Output Example

```
Found 107 profile(s) to scan
============================================================
[1/107] Scanning profile: ct-audit.admin (CT-Audit)
  Found 3 user(s)
[2/107] Scanning profile: ct-logarchive.admin (CT-LogArchive)
  Found 1 user(s)
...

============================================================
SCAN COMPLETE
============================================================
Profiles attempted: 107
Accounts scanned: 95
Accounts failed: 12
Total records: 450
```

## Troubleshooting

### "Credentials expired or unavailable" Error

Run AWS SSO login:
```bash
aws sso login
```

### "Access denied to IAM" Error

- The profile may not have IAM read permissions
- Check that the role has the required IAM permissions

### Some Accounts Skipped

This is normal if:
- SSO session expired for that account
- The role doesn't have IAM permissions
- The account is not accessible

### No Profiles Found

- Check that `~/.aws/config` exists
- Verify the profile pattern matches your naming convention
- Use `--profile-pattern` to adjust the filter

## Security Notes

- These scripts only read IAM data; they do not modify anything
- Results may contain sensitive information (usernames, key IDs)
- Store output files securely and delete when no longer needed
- The `.gitignore` excludes output files (*.csv, *.html, *.json) by default
