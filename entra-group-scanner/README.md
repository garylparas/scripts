# Entra ID Group Scanner

A Python script to list users in a Microsoft Entra ID (formerly Azure AD) group and check their account status.

## Features

- List all users in an Entra ID group
- Search group by name or ID
- View account enabled/disabled status
- See when users were added to the group (from audit logs)
- See last sign-in activity
- Compare group members with a list of emails from a file
- Export results to JSON

## Prerequisites

- Python 3.8 or higher
- An Azure/Entra ID App Registration with appropriate permissions

## Azure App Registration Setup

1. Go to [Azure Portal](https://portal.azure.com) > **Microsoft Entra ID** > **App registrations**

2. Click **New registration**:
   - Name: `Entra ID Group Scanner` (or any name you prefer)
   - Supported account types: Single tenant
   - Click **Register**

3. Note down the following from the **Overview** page:
   - **Application (client) ID** → `AZURE_CLIENT_ID`
   - **Directory (tenant) ID** → `AZURE_TENANT_ID`

4. Create a client secret:
   - Go to **Certificates & secrets** > **Client secrets** > **New client secret**
   - Add a description and expiration
   - Copy the **Value** immediately → `AZURE_CLIENT_SECRET`

5. Add API permissions:
   - Go to **API permissions** > **Add a permission**
   - Select **Microsoft Graph**
   - **IMPORTANT:** Choose **Application permissions** (NOT Delegated permissions)
     - Application permissions allow the script to run as a background service without user sign-in
     - Delegated permissions require interactive user login and will NOT work with this script
   - Add the following permissions:
     - `User.Read.All` (required)
     - `Group.Read.All` (required)
     - `AuditLog.Read.All` (optional, for sign-in activity)
   - Click **Grant admin consent for [Your Organization]** (requires admin privileges)

## Installation

1. Clone or navigate to the project directory:
   ```bash
   cd entra-group-scanner
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

   Edit `.env` and fill in your Azure credentials:
   ```
   AZURE_TENANT_ID=your-tenant-id
   AZURE_CLIENT_ID=your-client-id
   AZURE_CLIENT_SECRET=your-client-secret
   ```

## Usage

### Scan Group by Name

```bash
python check_group.py -n "Group Name"
```

### Scan Group by ID

```bash
python check_group.py -i "00000000-0000-0000-0000-000000000000"
```

### Verbose Output (Show All Details)

```bash
python check_group.py -n "IT Department" -v
```

### Export Results to JSON

```bash
python check_group.py -n "IT Department" -o results.json
```

### Show When Users Were Added to Group

```bash
python check_group.py -n "IT Department" -a
```

**Note:** This requires `AuditLog.Read.All` permission and audit logs are only retained for 30 days (or longer with Entra ID P1/P2 licenses).

### Compare with User List

Compare group members against a list of emails in a file:
```bash
python check_group.py -n "IT Department" -c users.txt
```

### Combine Options

```bash
python check_group.py -n "IT Department" -v -c users.txt -o results.json
```

## Input File Format (for comparison)

The `users.txt` file should contain one email address per line:

```
user1@example.com
user2@example.com
user3@example.com
```

Lines starting with `#` are treated as comments and ignored.

## Output

Example output:
```
Searching for group: IT Department

============================================================
GROUP: IT Department
ID: 00000000-0000-0000-0000-000000000000
Description: IT Department Staff
============================================================

Fetching group members...
Found 3 user(s) in the group.

============================================================
Display Name: John Doe
Email: john.doe@example.com
Status: ENABLED
Added to Group: 2024-06-15T10:30:00Z

============================================================
Display Name: Jane Smith
Email: jane.smith@example.com
Status: ENABLED
Added to Group: 2024-08-20T14:45:00Z

============================================================
Display Name: Bob Wilson
Email: bob.wilson@example.com
Status: DISABLED
Added to Group: 2024-03-10T09:15:00Z

============================================================
SUMMARY
============================================================
Group: IT Department
Total users: 3
  - Enabled: 2
  - Disabled: 1

DISABLED USERS:
  - Bob Wilson (bob.wilson@example.com)

============================================================
COMPARISON RESULTS
============================================================
File: users.txt
Users in file: 4
Users in group: 3

In GROUP but NOT in FILE (1):
  - Jane Smith (jane.smith@example.com)

In FILE but NOT in GROUP (2):
  - alice@example.com
  - charlie@example.com
```

## Troubleshooting

### "Insufficient privileges" Error
- Ensure admin consent was granted for the API permissions
- Verify the app has `User.Read.All` and `Group.Read.All` permissions
- **Make sure you added Application permissions, NOT Delegated permissions**

### "AADSTS700016" or "Application not found" Error
- Verify your `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` are correct
- Ensure the app registration exists in your tenant

### "Invalid client secret" Error
- Check that your client secret hasn't expired
- Regenerate the secret in Azure Portal if needed

### Sign-in Activity Shows "N/A"
- The `AuditLog.Read.All` permission is required for sign-in activity
- Sign-in activity is only available with Entra ID P1/P2 licenses

### Multiple Groups Found
- If multiple groups share the same name, use `--id` with the group GUID instead

## Security Notes

- Never commit your `.env` file to version control
- The `.env` file is excluded in `.gitignore` by default
- Rotate your client secret periodically
- Use the principle of least privilege when assigning permissions
