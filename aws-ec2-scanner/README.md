# AWS EC2 Scanner

Python script to scan EC2 resources (instances, EBS volumes, snapshots, load balancers) across multiple AWS accounts and regions using AWS CLI profiles.

## Scripts

| Script | Description |
|--------|-------------|
| `scan_ec2.py` | Scan EC2 resources across accounts and regions |

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
                "ec2:DescribeInstances",
                "ec2:DescribeVolumes",
                "ec2:DescribeSnapshots",
                "elasticloadbalancing:DescribeLoadBalancers"
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
   cd aws-ec2-scanner
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

## EC2 Scanner (`scan_ec2.py`)

Scans EC2 resources across multiple AWS accounts and regions.

### Resources Scanned

| Resource | Description |
|----------|-------------|
| EC2 Instances | Virtual machines with state, type, IPs, costs |
| EBS Volumes | Block storage volumes with type, size, IOPS |
| EBS Snapshots | Volume backups with size and state |
| Load Balancers | ALB, NLB, GLB, and Classic load balancers |

### Usage

```bash
# Basic scan (all admin profiles, us-east-1 and us-west-2)
python scan_ec2.py

# Verbose output
python scan_ec2.py -v

# Export to CSV/HTML/JSON
python scan_ec2.py --csv ec2_data --html ec2_report.html -o ec2_data.json

# Scan single profile
python scan_ec2.py --profile prod-platform.admin

# Use different profile pattern
python scan_ec2.py --profile-pattern ".readonly"

# Scan additional regions
python scan_ec2.py --regions us-east-1,us-west-2,eu-west-1,ap-southeast-1
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

#### EC2 Instances

| Column | Description |
|--------|-------------|
| AccountId | AWS Account ID |
| AccountName | AWS Account Name (from SSO config) |
| Region | AWS Region |
| InstanceId | EC2 Instance ID |
| InstanceName | Name tag value |
| InstanceType | Instance type (e.g., t3.micro, m5.large) |
| Platform | Linux or Windows |
| State | running, stopped, pending, terminated |
| ManagedBy | Ephemeral instance manager: ASG, EKS, Karpenter, or "No" for standalone |
| Schedule | Uptime schedule from "schedule" tag (for scheduled start/stop) |
| VpcId | VPC ID where instance runs |
| SubnetId | Subnet ID |
| PrivateIp | Private IP address |
| PublicIp | Public IP address (if assigned) |
| KeyName | SSH key pair name |
| IamRole | IAM instance profile role |
| EbsVolumes | Number of attached EBS volumes |
| SecurityGroups | Attached security group IDs |
| HourlyCost | Hourly cost (running instances only) |
| MonthlyCost | Estimated monthly cost (running instances only) |
| LaunchTime | Instance launch timestamp |

#### EBS Volumes

| Column | Description |
|--------|-------------|
| VolumeId | EBS Volume ID |
| VolumeName | Name tag value |
| VolumeType | gp2, gp3, io1, io2, st1, sc1, standard |
| Size | Volume size in GB |
| State | available, in-use, creating, deleting |
| Iops | Provisioned IOPS |
| Throughput | Provisioned throughput (gp3 only) |
| Encrypted | Yes or No |
| AttachedTo | Instance ID if attached |
| Device | Device name (e.g., /dev/sda1) |
| AttachmentState | attached or detached |
| AvailabilityZone | AZ where volume exists |
| SnapshotId | Source snapshot ID |
| MonthlyCost | Estimated monthly storage cost |
| CreateTime | Volume creation timestamp |

#### EBS Snapshots

| Column | Description |
|--------|-------------|
| SnapshotId | Snapshot ID |
| SnapshotName | Name tag value |
| VolumeId | Source volume ID |
| VolumeSize | Snapshot size in GB |
| State | completed, pending, error |
| Progress | Completion percentage |
| Encrypted | Yes or No |
| Description | Snapshot description |
| MonthlyCost | Estimated monthly storage cost |
| StartTime | Snapshot creation timestamp |

#### Load Balancers

| Column | Description |
|--------|-------------|
| LoadBalancerName | Load balancer name |
| LoadBalancerArn | ARN (N/A for Classic) |
| Type | APPLICATION, NETWORK, GATEWAY, CLASSIC |
| Scheme | internet-facing or internal |
| VpcId | VPC ID |
| State | active, provisioning, failed |
| DNSName | DNS hostname |
| AvailabilityZones | Deployed availability zones |
| SecurityGroups | Security groups (ALB/Classic only) |
| IpAddressType | ipv4 or dualstack |
| HourlyCost | Hourly base cost |
| MonthlyCost | Estimated monthly base cost |
| CreatedTime | Creation timestamp |

### HTML Report Features

- **Tabbed interface** for each resource type
- **Summary dashboard** with resource counts
- **Cost summary** with dynamic totals that update with filters
- **Filters per tab:**
  - Search (all columns)
  - Account dropdown
  - Region dropdown
  - Resource-specific filters (Instance state/platform, Volume type/state/encrypted, Snapshot state/encrypted, LB type/scheme)

### CSV Output

Creates multiple CSV files with the provided prefix:
- `{prefix}_instances.csv`
- `{prefix}_volumes.csv`
- `{prefix}_snapshots.csv`
- `{prefix}_load_balancers.csv`

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
  EC2 Instances: 1,245
  EBS Volumes: 3,890
  EBS Snapshots: 12,450
  Load Balancers: 156

Estimated Monthly Costs:
  EC2 Instances: $45,678.00
  EBS Volumes: $4,567.89
  EBS Snapshots: $1,234.56
  Load Balancers: $2,850.00
  Total: $54,330.45
```

## Troubleshooting

### "Credentials expired or unavailable" Error

Run AWS SSO login:
```bash
aws sso login
```

### "Access denied to EC2" Error

- The profile may not have EC2 read permissions
- Check that the role has the required EC2 permissions

### Some Accounts Skipped

This is normal if:
- SSO session expired for that account
- The role doesn't have EC2 permissions
- The account is not accessible

### No Profiles Found

- Check that `~/.aws/config` exists
- Verify the profile pattern matches your naming convention
- Use `--profile-pattern` to adjust the filter

## Pricing Notes

The scanner includes estimated costs for resources with hourly/monthly charges:

### EC2 Instance Pricing

The scanner includes on-demand pricing for 80+ common instance types (Linux and Windows). Sample rates:

| Instance Type | Linux/hr | Windows/hr | Notes |
|--------------|----------|------------|-------|
| t2.micro | $0.0116 | $0.0162 | Burstable, free tier eligible |
| t3.medium | $0.0416 | $0.0580 | Burstable, general purpose |
| m5.large | $0.096 | $0.188 | General purpose |
| m6i.xlarge | $0.192 | $0.376 | General purpose, Intel |
| c5.2xlarge | $0.340 | $0.540 | Compute optimized |
| r5.xlarge | $0.252 | $0.452 | Memory optimized |
| g4dn.xlarge | $0.526 | $0.822 | GPU instances |

Costs are only calculated for **running** instances. Stopped instances show N/A.

### EBS and Load Balancer Pricing

| Resource | Rate | Monthly Estimate | Notes |
|----------|------|------------------|-------|
| EBS gp2 | $0.10/GB | Varies by size | General purpose SSD |
| EBS gp3 | $0.08/GB | Varies by size | + IOPS/throughput if provisioned |
| EBS io1 | $0.125/GB + $0.065/IOPS | Varies | Provisioned IOPS SSD |
| EBS io2 | $0.125/GB + tiered IOPS | Varies | Provisioned IOPS SSD |
| EBS st1 | $0.045/GB | Varies by size | Throughput optimized HDD |
| EBS sc1 | $0.015/GB | Varies by size | Cold HDD |
| EBS Snapshots | $0.05/GB | Varies by size | Incremental storage |
| ALB | $0.0225/hr | ~$16.43 | + LCU charges |
| NLB | $0.0225/hr | ~$16.43 | + LCU charges |
| GLB | $0.0125/hr | ~$9.13 | + LCU charges |
| Classic LB | $0.025/hr | ~$18.25 | + data processing |

**Additional Charges (not included in scanner):**

| Resource | Charge | Notes |
|----------|--------|-------|
| EBS IOPS (io1/io2) | $0.065/IOPS | For provisioned IOPS volumes |
| EBS Throughput (gp3) | $0.04/MBps | Over 125 MBps baseline |
| LB LCU | $0.008/LCU-hour | Based on new connections, active connections, bandwidth, rule evaluations |
| Data Transfer | $0.09/GB | EC2 to internet (outbound) |
| Reserved/Spot Instances | Varies | Discounted pricing not calculated |

**Important:**
- Prices are based on US East (N. Virginia) region and may vary by region
- Monthly estimates assume 730 hours (average hours per month)
- Instance pricing covers on-demand rates only; reserved and spot instances may differ
- Unknown instance types show N/A (pricing dictionary covers 80+ common types)
- For current pricing, see [AWS EC2 Pricing](https://aws.amazon.com/ec2/pricing/) and [AWS EBS Pricing](https://aws.amazon.com/ebs/pricing/)

## Security Notes

- This script only reads EC2 data; it does not modify anything
- Results may contain sensitive information (IP addresses, instance names)
- Store output files securely and delete when no longer needed
- The `.gitignore` excludes output files (*.csv, *.html, *.json) by default
