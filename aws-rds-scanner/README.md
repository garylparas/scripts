# AWS RDS Scanner

Python script to scan RDS resources (DB instances, Aurora clusters, snapshots) across multiple AWS accounts and regions using AWS CLI profiles.

**Note:** This scanner only includes RDS and Aurora databases. DocumentDB clusters and instances are excluded.

## Scripts

| Script | Description |
|--------|-------------|
| `scan_rds.py` | Scan RDS resources across accounts and regions |

## Features

- Scan across multiple AWS accounts using profile patterns
- Multi-region support (default: us-east-1, us-west-2)
- Export results to CSV, HTML, or JSON
- **Interactive HTML reports** with tabbed interface, sorting, and filtering
- Account names extracted from AWS SSO config
- Graceful handling of expired SSO credentials
- Dynamic cost summary that updates with filters

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
                "rds:DescribeDBInstances",
                "rds:DescribeDBClusters",
                "rds:DescribeDBSnapshots",
                "rds:DescribeDBClusterSnapshots",
                "rds:DescribeReservedDBInstances"
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
   cd aws-rds-scanner
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

## RDS Scanner (`scan_rds.py`)

Scans RDS resources across multiple AWS accounts and regions.

### Resources Scanned

| Resource | Description |
|----------|-------------|
| DB Instances | RDS database instances with engine, class, costs |
| Aurora Clusters | Aurora DB clusters with storage, members |
| DB Snapshots | Manual RDS snapshots (automated excluded) |
| Cluster Snapshots | Manual Aurora cluster snapshots |
| Reserved Instances | Reserved DB instance purchases |

### Usage

```bash
# Basic scan (all admin profiles, us-east-1 and us-west-2)
python scan_rds.py

# Verbose output
python scan_rds.py -v

# Export to CSV/HTML/JSON
python scan_rds.py --csv rds_data --html rds_report.html -o rds_data.json

# Scan single profile
python scan_rds.py --profile prod-platform.admin

# Use different profile pattern
python scan_rds.py --profile-pattern ".readonly"

# Scan additional regions
python scan_rds.py --regions us-east-1,us-west-2,eu-west-1,ap-southeast-1
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Show detailed output |
| `-o, --output FILE` | Export to JSON file |
| `--csv PREFIX` | Export to CSV files (creates multiple files with prefix) |
| `--html FILE` | Export to HTML file |
| `--profile PROFILE` | Scan specific profile |
| `--profile-pattern PATTERN` | Profile pattern (default: `.admin`) |
| `--regions REGIONS` | Comma-separated regions (default: `us-east-1,us-west-2`) |

### Output Columns

#### DB Instances

| Column | Description |
|--------|-------------|
| AccountId | AWS Account ID |
| AccountName | AWS Account Name (from SSO config) |
| Region | AWS Region |
| DBInstanceId | RDS instance identifier |
| DBClusterId | Aurora cluster ID (if part of cluster) |
| InstanceClass | Instance class (e.g., db.t3.micro, db.m5.large) |
| Engine | Database engine (mysql, postgres, aurora-mysql, etc.) |
| EngineVersion | Engine version |
| Status | Instance status (available, stopped, etc.) |
| MultiAZ | Yes if Multi-AZ deployment |
| StorageType | Storage type (gp2, gp3, io1) |
| StorageGB | Allocated storage in GB |
| IOPS | Provisioned IOPS (if applicable) |
| Encrypted | Yes if storage encrypted |
| PubliclyAccessible | Yes if publicly accessible |
| BackupRetention | Backup retention period in days |
| HourlyCost | Hourly compute cost (available instances only) |
| MonthlyCost | Estimated monthly cost (compute + storage) |
| CreatedTime | Instance creation timestamp |

#### Aurora Clusters

| Column | Description |
|--------|-------------|
| ClusterId | Aurora cluster identifier |
| Engine | Database engine (aurora-mysql, aurora-postgresql) |
| EngineVersion | Engine version |
| Status | Cluster status |
| ClusterMembers | Number of instances in cluster |
| MultiAZ | Yes if multiple instances |
| StorageGB | Cluster storage size |
| Encrypted | Yes if storage encrypted |
| DeletionProtection | Yes if deletion protection enabled |
| BackupRetention | Backup retention period in days |
| MonthlyStorageCost | Estimated monthly storage cost |
| CreatedTime | Cluster creation timestamp |

#### Manual DB Snapshots

| Column | Description |
|--------|-------------|
| SnapshotId | Snapshot identifier |
| DBInstanceId | Source DB instance |
| Engine | Database engine |
| EngineVersion | Engine version |
| SnapshotType | Snapshot type (manual) |
| Status | Snapshot status |
| StorageGB | Snapshot size in GB |
| Encrypted | Yes if encrypted |
| MonthlyCost | Estimated monthly storage cost ($0.095/GB-month) |
| CreatedTime | Snapshot creation timestamp |

**Note:** Only manual snapshots are included. Automated backups are excluded as their cost depends on total backup storage vs. provisioned storage (free up to provisioned size).

#### Reserved DB Instances

| Column | Description |
|--------|-------------|
| ReservedId | Reserved instance ID |
| InstanceClass | Instance class |
| ProductDescription | Engine and license type |
| State | Reservation state (active, retired) |
| OfferingType | Payment option (All Upfront, Partial, No Upfront) |
| MultiAZ | Yes if Multi-AZ |
| Duration | Reservation term in years |
| InstanceCount | Number of instances |
| FixedPrice | Upfront payment amount |
| RecurringCharges | Hourly recurring charge |
| StartTime | Reservation start time |

### HTML Report Features

- **Tabbed interface** for each resource type
- **Summary dashboard** with resource counts
- **Cost summary** with dynamic totals that update with filters
- **Filters per tab:**
  - Search (all columns)
  - Account dropdown
  - Region dropdown
  - Engine filter (DB instances, clusters, snapshots)
  - Status filter (DB instances, clusters)
  - Multi-AZ filter (DB instances)

### CSV Output

Creates multiple CSV files with the provided prefix:
- `{prefix}_instances.csv`
- `{prefix}_clusters.csv`
- `{prefix}_snapshots.csv`
- `{prefix}_cluster_snapshots.csv`
- `{prefix}_reserved.csv`

---

## Console Output Example

```
Found 107 profile(s) to scan
Regions: us-east-1, us-west-2
============================================================
[1/107] Scanning profile: ct-audit.admin (CT-Audit)
  Scanning region: us-east-1
  Scanning region: us-west-2
[2/107] Scanning profile: ct-logarchive.admin (CT-LogArchive)
  Scanning region: us-east-1
  Scanning region: us-west-2
...

============================================================
SCAN COMPLETE
============================================================
Profiles attempted: 107
Accounts scanned: 95
Accounts failed: 12
Regions scanned: us-east-1, us-west-2

Resources Found:
  DB Instances: 245
  Aurora Clusters: 45
  DB Snapshots: 156
  Cluster Snapshots: 89
  Reserved Instances: 23

Estimated Monthly Costs:
  DB Instances: $45,678.00
  Aurora Storage: $1,234.56
  Snapshots: $567.89
  Total: $47,480.45
  (Note: Costs are on-demand pricing, us-east-1. Actual costs may be lower with Reserved Instances.)
```

## Troubleshooting

### "Credentials expired or unavailable" Error

Run AWS SSO login:
```bash
aws sso login
```

### "Access denied to RDS" Error

- The profile may not have RDS read permissions
- Check that the role has the required RDS permissions

### Some Accounts Skipped

This is normal if:
- SSO session expired for that account
- The role doesn't have RDS permissions
- The account is not accessible

### No Profiles Found

- Check that `~/.aws/config` exists
- Verify the profile pattern matches your naming convention
- Use `--profile-pattern` to adjust the filter

## Pricing Notes

The scanner includes estimated costs for resources with hourly/monthly charges:

### RDS Instance Pricing

The scanner includes on-demand pricing for common instance types:

| Instance Family | Description | Notes |
|----------------|-------------|-------|
| db.t3, db.t4g | Burstable | Good for dev/test |
| db.m5, db.m6i, db.m6g, db.m7g | General Purpose | Balanced compute/memory |
| db.r5, db.r6i, db.r6g, db.r7g | Memory Optimized | High memory workloads |
| db.x2g | Memory Optimized Extreme | Very high memory |

Sample rates (us-east-1, Single-AZ):

| Instance Type | $/Hour | Notes |
|--------------|--------|-------|
| db.t3.micro | $0.017 | Free tier eligible |
| db.t3.medium | $0.068 | Burstable |
| db.m5.large | $0.171 | General purpose |
| db.m6i.xlarge | $0.342 | General purpose |
| db.r5.large | $0.250 | Memory optimized |
| db.r6i.2xlarge | $1.000 | Memory optimized |

### Aurora Serverless v2 Pricing

| Resource | Price | Notes |
|----------|-------|-------|
| ACU-hour | $0.12 | Per Aurora Capacity Unit per hour |

- Serverless instances display as `db.serverless (min-max ACU)` showing the configured capacity range
- Cost estimates use the **minimum ACU** as a baseline; actual costs depend on usage
- Each ACU provides approximately 2 GB of memory

### Storage Pricing

| Storage Type | $/GB-month | Notes |
|-------------|-----------|-------|
| gp2 | $0.115 | General Purpose SSD |
| gp3 | $0.08 | General Purpose SSD |
| io1 | $0.125 + $0.10/IOPS | Provisioned IOPS |
| Aurora | $0.10 | Aurora storage |
| Backups | $0.095 | Over provisioned storage |

**Additional Charges (not included in scanner):**

| Resource | Charge | Notes |
|----------|--------|-------|
| Multi-AZ | ~2x | Double the Single-AZ price |
| Data Transfer | $0.09/GB | Outbound to internet |
| I/O Requests | $0.20/million | Aurora I/O |
| Extended Support | Varies | For older engine versions |

**Important:**
- Prices are based on US East (N. Virginia) region and may vary by region
- Monthly estimates assume 730 hours (average hours per month)
- Multi-AZ deployments are approximately 2x the Single-AZ price
- Reserved Instances offer up to 60% savings over On-Demand
- For current pricing, see [AWS RDS Pricing](https://aws.amazon.com/rds/pricing/)

## Security Notes

- This script only reads RDS data; it does not modify anything
- Results may contain sensitive information (endpoints, instance names)
- Store output files securely and delete when no longer needed
- The `.gitignore` excludes output files (*.csv, *.html, *.json) by default
