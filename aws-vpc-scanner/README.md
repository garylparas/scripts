# AWS VPC Scanner

Python script to scan VPC resources across multiple AWS accounts and regions using AWS CLI profiles.

## Scripts

| Script | Description |
|--------|-------------|
| `scan_vpcs.py` | Scan VPC resources across accounts and regions |

## Features

- Scan across multiple AWS accounts using profile patterns
- Multi-region support (default: us-east-1, us-west-2)
- Export results to CSV, HTML, or JSON
- **Interactive HTML reports** with tabbed interface, sorting, and filtering
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
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
                "ec2:DescribeInternetGateways",
                "ec2:DescribeNatGateways",
                "ec2:DescribeRouteTables",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeVpcPeeringConnections",
                "ec2:DescribeFlowLogs",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeAddresses",
                "ec2:DescribeTransitGatewayAttachments"
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
   cd aws-vpc-scanner
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

## VPC Scanner (`scan_vpcs.py`)

Scans VPC resources across multiple AWS accounts and regions.

### Resources Scanned

| Resource | Description |
|----------|-------------|
| VPCs | Virtual Private Clouds |
| Subnets | Public and private subnets |
| Internet Gateways | IGWs for public internet access |
| NAT Gateways | NATs for private subnet internet access |
| Route Tables | Routing configurations |
| Security Groups | Network security rules |
| VPC Endpoints | Private connections to AWS services |
| VPC Peering | Peering connections between VPCs |
| Flow Logs | VPC, subnet, and ENI flow logs |
| Elastic IPs | Elastic IP addresses and associations |
| Transit Gateway Attachments | TGW VPC, VPN, and Direct Connect attachments |

### Usage

```bash
# Basic scan (all admin profiles, us-east-1 and us-west-2)
python scan_vpcs.py

# Verbose output
python scan_vpcs.py -v

# Export to CSV/HTML/JSON
python scan_vpcs.py --csv vpc_data.csv --html vpc_report.html -o vpc_data.json

# Scan single profile
python scan_vpcs.py --profile prod-platform.admin

# Use different profile pattern
python scan_vpcs.py --profile-pattern ".readonly"

# Scan additional regions
python scan_vpcs.py --regions us-east-1,us-west-2,eu-west-1,ap-southeast-1
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Show detailed output |
| `-o, --output FILE` | Export to JSON file |
| `--csv FILE` | Export to CSV files (creates multiple files with prefix) |
| `--html FILE` | Export to HTML file |
| `--profile PROFILE` | Scan specific profile |
| `--profile-pattern PATTERN` | Profile pattern (default: `.admin`) |
| `--regions REGIONS` | Comma-separated regions (default: `us-east-1,us-west-2`) |

### Output Columns

#### VPCs

| Column | Description |
|--------|-------------|
| AccountId | AWS Account ID |
| AccountName | AWS Account Name (from SSO config) |
| Region | AWS Region |
| VpcId | VPC ID |
| VpcName | Name tag value |
| CidrBlock | VPC CIDR range |
| State | VPC state (available/pending) |
| FlowLogsEnabled | Yes if VPC has flow logs enabled |

#### Subnets

| Column | Description |
|--------|-------------|
| SubnetId | Subnet ID |
| SubnetName | Name tag value |
| VpcId | Parent VPC ID |
| CidrBlock | Subnet CIDR range |
| AvailabilityZone | AWS Availability Zone |
| AvailableIps | Available IP address count |
| IsPublic | Yes if subnet has route to IGW |
| MapPublicIp | Auto-assign public IP setting |
| State | Subnet state |

#### Internet Gateways

| Column | Description |
|--------|-------------|
| InternetGatewayId | IGW ID |
| IgwName | Name tag value |
| VpcId | Attached VPC ID |
| State | Attachment state (available/detached) |

#### NAT Gateways

| Column | Description |
|--------|-------------|
| NatGatewayId | NAT Gateway ID |
| NatName | Name tag value |
| VpcId | Parent VPC ID |
| SubnetId | Subnet where NAT is deployed |
| Availability | Zonal with AZ name (e.g., "Zonal (us-east-1a)") |
| State | NAT state (available/pending/failed/deleted) |
| ConnectivityType | public or private |
| PublicIp | Elastic IP address |
| HourlyCost | Hourly cost ($0.045/hr when available) |
| MonthlyCost | Estimated monthly cost (~$32.85/month) |
| CreateTime | Creation timestamp |

#### Route Tables

| Column | Description |
|--------|-------------|
| RouteTableId | Route Table ID |
| RtName | Name tag value |
| VpcId | Parent VPC ID |
| IsMain | Yes if this is the main route table |
| RoutesCount | Number of routes |
| AssociatedSubnets | Number of associated subnets |

#### Security Groups

| Column | Description |
|--------|-------------|
| SecurityGroupId | Security Group ID |
| SecurityGroupName | Security Group name |
| VpcId | Parent VPC ID |
| Description | Security Group description |
| InboundRulesCount | Number of inbound rules |
| OutboundRulesCount | Number of outbound rules |
| InUse | Yes if attached to ENI or referenced by another SG |
| UsedBy | Details: ENI count and/or SG IDs that reference this SG (e.g., "5 ENIs; sg-abc123, sg-def456") |

#### VPC Endpoints

| Column | Description |
|--------|-------------|
| VpcEndpointId | Endpoint ID |
| EndpointName | Name tag value |
| VpcId | Parent VPC ID |
| ServiceName | AWS service name |
| EndpointType | Gateway or Interface |
| State | Endpoint state |
| HourlyCost | Hourly cost ($0.01/hr for Interface, $0 for Gateway) |
| MonthlyCost | Estimated monthly cost (~$7.30/month for Interface) |
| CreationTime | Creation timestamp |

#### VPC Peering

| Column | Description |
|--------|-------------|
| PeeringConnectionId | Peering connection ID |
| PeeringName | Name tag value |
| RequesterVpcId | Requester VPC ID |
| RequesterCidr | Requester VPC CIDR |
| RequesterAccountId | Requester AWS Account ID |
| AccepterVpcId | Accepter VPC ID |
| AccepterCidr | Accepter VPC CIDR |
| AccepterAccountId | Accepter AWS Account ID |
| Status | Peering status (active/pending-acceptance/deleted) |

#### Flow Logs

| Column | Description |
|--------|-------------|
| FlowLogId | Flow log ID |
| FlowLogName | Name tag value |
| ResourceId | VPC, subnet, or ENI ID |
| ResourceType | VPC, Subnet, or NetworkInterface |
| TrafficType | ACCEPT, REJECT, or ALL |
| Status | Flow log status (ACTIVE) |
| DestinationType | cloud-watch-logs or s3 |
| Destination | CloudWatch log group or S3 bucket ARN |
| CreationTime | Creation timestamp |

#### Elastic IPs

| Column | Description |
|--------|-------------|
| AllocationId | Elastic IP allocation ID |
| PublicIp | Public IP address |
| EipName | Name tag value |
| PrivateIp | Associated private IP address |
| AssociatedWith | Instance ID, ENI ID, or None |
| NatGatewayId | NAT Gateway ID if EIP is associated with a NAT Gateway |
| Status | Associated or Available |
| HourlyCost | Hourly cost ($0.005/hr for all public IPv4) |
| MonthlyCost | Estimated monthly cost (~$3.65/month) |
| Domain | vpc or standard |
| NetworkBorderGroup | Network border group |

#### Transit Gateway Attachments

| Column | Description |
|--------|-------------|
| TransitGatewayAttachmentId | TGW attachment ID |
| TransitGatewayId | Transit Gateway ID |
| TransitGatewayOwnerId | AWS Account ID that owns the TGW |
| ResourceOwnerId | AWS Account ID that owns the attached resource |
| ResourceType | Type of attached resource (vpc, vpn, direct-connect-gateway, peering, connect) |
| ResourceId | ID of the attached resource (VPC ID, VPN ID, etc.) |
| State | Attachment state (available, pending, deleting, deleted) |
| AttachmentName | Name tag value |
| HourlyCost | Hourly cost ($0.05/hr per attachment when available) |
| MonthlyCost | Estimated monthly cost (~$36.50/month) |
| CreationTime | Creation timestamp |

### HTML Report Features

- **Tabbed interface** for each resource type
- **Summary dashboard** with resource counts
- **Filters per tab:**
  - Search (all columns)
  - Account dropdown
  - Region dropdown
  - Resource-specific filters (VPC Flow Logs, Public/Private subnets, NAT state, SG In Use, Endpoint type, Peering status, Flow Log resource type and destination type, Elastic IP status, TGW resource type and state)

### CSV Output

Creates multiple CSV files with the provided prefix:
- `{prefix}_vpcs.csv`
- `{prefix}_subnets.csv`
- `{prefix}_igws.csv`
- `{prefix}_nats.csv`
- `{prefix}_route_tables.csv`
- `{prefix}_security_groups.csv`
- `{prefix}_endpoints.csv`
- `{prefix}_peering.csv`
- `{prefix}_flow_logs.csv`
- `{prefix}_elastic_ips.csv`
- `{prefix}_transit_gateway_attachments.csv`

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
  VPCs: 245
  Subnets: 1,230
  Internet Gateways: 198
  NAT Gateways: 156
  Route Tables: 890
  Security Groups: 2,450
  VPC Endpoints: 320
  VPC Peering: 45
  Flow Logs: 180
  Elastic IPs: 95
  TGW Attachments: 42
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

The scanner includes estimated costs for resources with hourly charges:

| Resource | Hourly Rate | Monthly Estimate | Notes |
|----------|-------------|------------------|-------|
| NAT Gateway | $0.045 | ~$32.85 | Only when state is "available" |
| VPC Interface Endpoint | $0.01 | ~$7.30 | Per AZ; Gateway endpoints are free |
| Elastic IP | $0.005 | ~$3.65 | All public IPv4 addresses (as of Feb 2024) |
| Transit Gateway Attachment | $0.05 | ~$36.50 | Per attachment when state is "available" |

**Additional Data Transfer Charges (not included in scanner):**

| Resource | Data Charge | Notes |
|----------|-------------|-------|
| NAT Gateway | $0.045/GB | Data processed through the gateway |
| VPC Interface Endpoint | $0.01/GB | Data processed through the endpoint |
| VPC Peering | $0.01/GB | Both inbound and outbound directions |
| Internet Gateway | $0.09/GB | EC2 to internet (outbound); inbound is free |
| Transit Gateway | $0.02/GB | Data processed through the gateway |
| Flow Logs | Varies | Publishing & storage costs (CloudWatch Logs, S3, or Kinesis Data Firehose) |

**Important:**
- Prices are based on US East (N. Virginia) region and may vary by region
- Monthly estimates assume 730 hours (average hours per month)
- For current pricing, see [AWS VPC Pricing](https://aws.amazon.com/vpc/pricing/) and [AWS Transit Gateway Pricing](https://aws.amazon.com/transit-gateway/pricing/)

## Security Notes

- This script only reads VPC data; it does not modify anything
- Results may contain sensitive information (CIDR ranges, security group rules)
- Store output files securely and delete when no longer needed
- The `.gitignore` excludes output files (*.csv, *.html, *.json) by default
