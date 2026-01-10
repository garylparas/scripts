# Entra ID User Scanner

A Python script to check the status of user accounts in Microsoft Entra ID (formerly Azure AD) from a list of email addresses.

## Features

- Check if users exist in Entra ID
- View account enabled/disabled status
- See last sign-in activity
- Export results to JSON
- Supports single email or batch processing from file

## Prerequisites

- Python 3.8 or higher
- An Azure/Entra ID App Registration with appropriate permissions

## Azure App Registration Setup

1. Go to [Azure Portal](https://portal.azure.com) > **Microsoft Entra ID** > **App registrations**

2. Click **New registration**:
   - Name: `Entra ID User Scanner` (or any name you prefer)
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
     - `AuditLog.Read.All` (optional, for sign-in activity)
   - Click **Grant admin consent for [Your Organization]** (requires admin privileges)

## Installation

1. Clone or navigate to the project directory:
   ```bash
   cd entra-id-user-scanner
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

### Basic Usage

Check users from the default `users.txt` file:
```bash
python check_users.py
```

### Check a Single Email

```bash
python check_users.py -e user@example.com
```

### Use a Different Input File

```bash
python check_users.py -f path/to/emails.txt
```

### Verbose Output (Show All Details)

```bash
python check_users.py -v
```

### Export Results to JSON

```bash
python check_users.py -o results.json
```

### Combine Options

```bash
python check_users.py -f users.txt -v -o results.json
```

## Input File Format

The `users.txt` file should contain one email address per line:

```
user1@example.com
user2@example.com
user3@example.com
```

Lines starting with `#` are treated as comments and ignored.

## Output

The script displays:
- User email and display name
- Account status (ENABLED/DISABLED/NOT FOUND)
- Verbose mode includes: creation date, last password change, sign-in activity

Example output:
```
Checking 3 user(s) in Entra ID...

============================================================
Email: john.doe@example.com
Display Name: John Doe
Status: ENABLED

============================================================
Email: jane.smith@example.com
Display Name: Jane Smith
Status: DISABLED

============================================================
Email: unknown@example.com
Status: NOT FOUND
Error: User not found

============================================================
SUMMARY
============================================================
Total checked: 3
Found: 2
  - Enabled: 1
  - Disabled: 1
Not found: 1
```

## Troubleshooting

### "Insufficient privileges" Error
- Ensure admin consent was granted for the API permissions
- Verify the app has `User.Read.All` permission
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

## Security Notes

- Never commit your `.env` file to version control
- The `.env` file is excluded in `.gitignore` by default
- Rotate your client secret periodically
- Use the principle of least privilege when assigning permissions
