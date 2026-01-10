#!/usr/bin/env python3
"""
AWS EC2 Scanner

Scans EC2 resources (instances, EBS volumes, load balancers) across multiple
AWS accounts and regions, iterating through AWS profiles.
"""

import os
import sys
import csv
import json
import argparse
import configparser
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, ProfileNotFound, NoCredentialsError, TokenRetrievalError, SSOTokenLoadError

from ec2_pricing import EC2_PRICING, HOURS_PER_MONTH, get_instance_hourly_cost


DEFAULT_REGIONS = ["us-east-1", "us-west-2"]

# AWS Pricing (USD) - as of 2024, us-east-1 region
# https://aws.amazon.com/ebs/pricing/
# https://aws.amazon.com/elasticloadbalancing/pricing/
PRICING = {
    # EBS Volume pricing per GB-month (us-east-1)
    "ebs_gp2_per_gb": 0.10,
    "ebs_gp3_per_gb": 0.08,
    "ebs_io1_per_gb": 0.125,
    "ebs_io2_per_gb": 0.125,
    "ebs_st1_per_gb": 0.045,
    "ebs_sc1_per_gb": 0.015,
    "ebs_standard_per_gb": 0.05,
    # Load Balancer pricing per hour
    "alb_hourly": 0.0225,
    "nlb_hourly": 0.0225,
    "glb_hourly": 0.0125,
    "clb_hourly": 0.025,
}


def get_aws_profiles(pattern: str = ".admin") -> dict:
    """Get all AWS profiles matching the pattern from ~/.aws/config.

    Returns a dict mapping profile_name -> account_name.
    """
    config_path = Path.home() / ".aws" / "config"

    if not config_path.exists():
        print(f"Error: AWS config file not found at {config_path}")
        return {}

    config = configparser.ConfigParser()
    config.read(config_path)

    profiles = {}
    for section in config.sections():
        if section.startswith("profile "):
            profile_name = section.replace("profile ", "")
            if pattern in profile_name:
                # Get account name from sso_account_name if available
                account_name = config.get(section, "sso_account_name", fallback=profile_name)
                profiles[profile_name] = account_name

    return dict(sorted(profiles.items()))


def get_account_id(session: boto3.Session) -> Optional[str]:
    """Get AWS Account ID using STS."""
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        return identity["Account"]
    except (ClientError, NoCredentialsError, TokenRetrievalError, SSOTokenLoadError) as e:
        return None
    except Exception as e:
        # Catch any other credential-related errors
        if "token" in str(e).lower() or "credential" in str(e).lower() or "sso" in str(e).lower():
            return None
        raise


def get_resource_name(tags: list) -> str:
    """Extract Name tag from resource tags."""
    if not tags:
        return "N/A"
    for tag in tags:
        if tag.get("Key") == "Name":
            return tag.get("Value", "N/A")
    return "N/A"


def get_managed_by(tags: list) -> str:
    """Determine if instance is managed/ephemeral (ASG, EKS, Karpenter).

    Returns a string indicating what manages the instance:
    - ASG: <name> - Auto Scaling Group
    - EKS: <cluster>/<nodegroup> - EKS Managed Node Group
    - Karpenter: <nodepool> - Karpenter provisioned
    - No - Standalone instance
    """
    if not tags:
        return "No"

    tag_dict = {tag.get("Key"): tag.get("Value") for tag in tags}

    # Check for Karpenter (takes precedence as it's more specific)
    karpenter_nodepool = tag_dict.get("karpenter.sh/nodepool")
    karpenter_provisioner = tag_dict.get("karpenter.sh/provisioner-name")
    if karpenter_nodepool:
        return f"Karpenter: {karpenter_nodepool}"
    if karpenter_provisioner:
        return f"Karpenter: {karpenter_provisioner}"

    # Check for EKS Managed Node Group
    eks_cluster = tag_dict.get("eks:cluster-name")
    eks_nodegroup = tag_dict.get("eks:nodegroup-name")
    if eks_cluster and eks_nodegroup:
        return f"EKS: {eks_cluster}/{eks_nodegroup}"
    if eks_cluster:
        return f"EKS: {eks_cluster}"

    # Check for Auto Scaling Group
    asg_name = tag_dict.get("aws:autoscaling:groupName")
    if asg_name:
        return f"ASG: {asg_name}"

    return "No"


def get_tag_value(tags: list, tag_key: str) -> str:
    """Extract a specific tag value from resource tags."""
    if not tags:
        return "N/A"
    for tag in tags:
        if tag.get("Key", "").lower() == tag_key.lower():
            return tag.get("Value", "N/A")
    return "N/A"


def get_ec2_instances(ec2_client) -> list:
    """Get all EC2 instances."""
    instances = []
    paginator = ec2_client.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            instances.extend(reservation.get("Instances", []))
    return instances


def get_ebs_volumes(ec2_client) -> list:
    """Get all EBS volumes."""
    volumes = []
    paginator = ec2_client.get_paginator("describe_volumes")
    for page in paginator.paginate():
        volumes.extend(page.get("Volumes", []))
    return volumes


def get_ebs_snapshots(ec2_client, owner_id: str) -> list:
    """Get all EBS snapshots owned by the account."""
    snapshots = []
    paginator = ec2_client.get_paginator("describe_snapshots")
    for page in paginator.paginate(OwnerIds=[owner_id]):
        snapshots.extend(page.get("Snapshots", []))
    return snapshots


def get_load_balancers_v2(elbv2_client) -> list:
    """Get all ALB/NLB/GLB load balancers."""
    lbs = []
    paginator = elbv2_client.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        lbs.extend(page.get("LoadBalancers", []))
    return lbs


def get_classic_load_balancers(elb_client) -> list:
    """Get all Classic load balancers."""
    lbs = []
    paginator = elb_client.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        lbs.extend(page.get("LoadBalancerDescriptions", []))
    return lbs


def calculate_ebs_monthly_cost(volume_type: str, size_gb: int, iops: int = 0, throughput: int = 0) -> float:
    """Calculate estimated monthly cost for an EBS volume."""
    volume_type = volume_type.lower()

    if volume_type == "gp2":
        return size_gb * PRICING["ebs_gp2_per_gb"]
    elif volume_type == "gp3":
        # gp3: $0.08/GB + $0.005/IOPS over 3000 + $0.04/MBps over 125
        base_cost = size_gb * PRICING["ebs_gp3_per_gb"]
        extra_iops_cost = max(0, iops - 3000) * 0.005
        extra_throughput_cost = max(0, throughput - 125) * 0.04
        return base_cost + extra_iops_cost + extra_throughput_cost
    elif volume_type == "io1":
        # io1: $0.125/GB + $0.065/IOPS
        return size_gb * PRICING["ebs_io1_per_gb"] + iops * 0.065
    elif volume_type == "io2":
        # io2: $0.125/GB + tiered IOPS pricing
        base_cost = size_gb * PRICING["ebs_io2_per_gb"]
        if iops <= 32000:
            iops_cost = iops * 0.065
        elif iops <= 64000:
            iops_cost = 32000 * 0.065 + (iops - 32000) * 0.046
        else:
            iops_cost = 32000 * 0.065 + 32000 * 0.046 + (iops - 64000) * 0.032
        return base_cost + iops_cost
    elif volume_type == "st1":
        return size_gb * PRICING["ebs_st1_per_gb"]
    elif volume_type == "sc1":
        return size_gb * PRICING["ebs_sc1_per_gb"]
    elif volume_type == "standard":
        return size_gb * PRICING["ebs_standard_per_gb"]
    else:
        return size_gb * PRICING["ebs_gp2_per_gb"]  # Default to gp2


def calculate_lb_monthly_cost(lb_type: str) -> float:
    """Calculate estimated monthly cost for a load balancer (base cost only)."""
    if lb_type == "application":
        return PRICING["alb_hourly"] * HOURS_PER_MONTH
    elif lb_type == "network":
        return PRICING["nlb_hourly"] * HOURS_PER_MONTH
    elif lb_type == "gateway":
        return PRICING["glb_hourly"] * HOURS_PER_MONTH
    else:  # classic
        return PRICING["clb_hourly"] * HOURS_PER_MONTH


def scan_accounts(profiles: dict, regions: list, verbose: bool = False) -> dict:
    """Scan EC2 resources across all profiles and regions."""
    results = {
        "instances": [],
        "volumes": [],
        "snapshots": [],
        "load_balancers": [],
        "scan_info": {
            "profiles_attempted": 0,
            "accounts_scanned": 0,
            "accounts_failed": 0,
            "regions": regions,
        }
    }

    total_profiles = len(profiles)
    scanned_accounts = set()
    failed_accounts = set()

    for idx, (profile_name, account_name) in enumerate(profiles.items(), 1):
        results["scan_info"]["profiles_attempted"] += 1
        print(f"[{idx}/{total_profiles}] Scanning profile: {profile_name} ({account_name})")

        try:
            session = boto3.Session(profile_name=profile_name)
            account_id = get_account_id(session)

            if not account_id:
                print(f"  Skipping - credentials expired or unavailable")
                failed_accounts.add(profile_name)
                continue

            scanned_accounts.add(account_id)

            for region in regions:
                if verbose:
                    print(f"  Scanning region: {region}")

                try:
                    ec2 = session.client("ec2", region_name=region)
                    elbv2 = session.client("elbv2", region_name=region)
                    elb = session.client("elb", region_name=region)

                    # Get resources
                    instances = get_ec2_instances(ec2)
                    volumes = get_ebs_volumes(ec2)
                    snapshots = get_ebs_snapshots(ec2, account_id)
                    lbs_v2 = get_load_balancers_v2(elbv2)
                    lbs_classic = get_classic_load_balancers(elb)

                    if verbose:
                        print(f"    Instances: {len(instances)}, Volumes: {len(volumes)}, Snapshots: {len(snapshots)}, LBs: {len(lbs_v2) + len(lbs_classic)}")

                    # Process EC2 Instances
                    for instance in instances:
                        instance_state = instance.get("State", {}).get("Name", "N/A")

                        # Get security group names
                        sg_names = [sg.get("GroupName", "") for sg in instance.get("SecurityGroups", [])]
                        sg_ids = [sg.get("GroupId", "") for sg in instance.get("SecurityGroups", [])]

                        # Get IAM role
                        iam_profile = instance.get("IamInstanceProfile", {})
                        iam_role = iam_profile.get("Arn", "").split("/")[-1] if iam_profile else "N/A"

                        # Get EBS volume count
                        ebs_count = len(instance.get("BlockDeviceMappings", []))

                        # Get platform
                        platform = instance.get("PlatformDetails", "Linux/UNIX")
                        if "Windows" in platform:
                            platform = "Windows"
                        elif "Linux" in platform or "UNIX" in platform:
                            platform = "Linux"

                        # Calculate instance cost (only for running instances)
                        instance_type = instance.get("InstanceType", "")
                        hourly_cost = get_instance_hourly_cost(instance_type, platform) if instance_state == "running" else 0.0
                        monthly_cost = hourly_cost * HOURS_PER_MONTH

                        # Check if instance is managed/ephemeral (ASG, EKS, Karpenter)
                        managed_by = get_managed_by(instance.get("Tags"))

                        # Get uptime schedule from tag
                        schedule = get_tag_value(instance.get("Tags"), "schedule")

                        results["instances"].append({
                            "AccountId": account_id,
                            "AccountName": account_name,
                            "Region": region,
                            "InstanceId": instance.get("InstanceId", "N/A"),
                            "InstanceName": get_resource_name(instance.get("Tags")),
                            "InstanceType": instance.get("InstanceType", "N/A"),
                            "Platform": platform,
                            "State": instance_state,
                            "ManagedBy": managed_by,
                            "Schedule": schedule,
                            "VpcId": instance.get("VpcId", "N/A"),
                            "SubnetId": instance.get("SubnetId", "N/A"),
                            "PrivateIp": instance.get("PrivateIpAddress", "N/A"),
                            "PublicIp": instance.get("PublicIpAddress", "N/A"),
                            "KeyName": instance.get("KeyName", "N/A"),
                            "IamRole": iam_role,
                            "EbsVolumes": ebs_count,
                            "SecurityGroups": ", ".join(sg_ids),
                            "HourlyCost": f"${hourly_cost:.4f}" if hourly_cost > 0 else "N/A",
                            "MonthlyCost": f"${monthly_cost:.2f}" if monthly_cost > 0 else "N/A",
                            "LaunchTime": instance.get("LaunchTime", "").strftime("%Y-%m-%d %H:%M:%S") if instance.get("LaunchTime") else "N/A",
                        })

                    # Process EBS Volumes
                    for volume in volumes:
                        vol_state = volume.get("State", "N/A")
                        vol_type = volume.get("VolumeType", "gp2")
                        size_gb = volume.get("Size", 0)
                        iops = volume.get("Iops", 0)
                        throughput = volume.get("Throughput", 0)

                        # Get attached instance
                        attachments = volume.get("Attachments", [])
                        attached_to = attachments[0].get("InstanceId", "N/A") if attachments else "N/A"
                        attachment_state = attachments[0].get("State", "N/A") if attachments else "detached"
                        device = attachments[0].get("Device", "N/A") if attachments else "N/A"

                        # Calculate cost
                        monthly_cost = calculate_ebs_monthly_cost(vol_type, size_gb, iops, throughput)

                        results["volumes"].append({
                            "AccountId": account_id,
                            "AccountName": account_name,
                            "Region": region,
                            "VolumeId": volume.get("VolumeId", "N/A"),
                            "VolumeName": get_resource_name(volume.get("Tags")),
                            "VolumeType": vol_type,
                            "Size": size_gb,
                            "State": vol_state,
                            "Iops": iops,
                            "Throughput": throughput if throughput else "N/A",
                            "Encrypted": "Yes" if volume.get("Encrypted") else "No",
                            "AttachedTo": attached_to,
                            "Device": device,
                            "AttachmentState": attachment_state,
                            "AvailabilityZone": volume.get("AvailabilityZone", "N/A"),
                            "SnapshotId": volume.get("SnapshotId", "N/A") if volume.get("SnapshotId") else "N/A",
                            "MonthlyCost": f"${monthly_cost:.2f}",
                            "CreateTime": volume.get("CreateTime", "").strftime("%Y-%m-%d %H:%M:%S") if volume.get("CreateTime") else "N/A",
                        })

                    # Process EBS Snapshots
                    for snapshot in snapshots:
                        # Skip Wiz auto-generated snapshots
                        description = snapshot.get("Description", "") or ""
                        if "auto-generated by Wiz" in description:
                            continue

                        snap_state = snapshot.get("State", "N/A")
                        size_gb = snapshot.get("VolumeSize", 0)
                        # Snapshot storage: ~$0.05/GB-month
                        monthly_cost = size_gb * 0.05

                        results["snapshots"].append({
                            "AccountId": account_id,
                            "AccountName": account_name,
                            "Region": region,
                            "SnapshotId": snapshot.get("SnapshotId", "N/A"),
                            "SnapshotName": get_resource_name(snapshot.get("Tags")),
                            "VolumeId": snapshot.get("VolumeId", "N/A"),
                            "VolumeSize": size_gb,
                            "State": snap_state,
                            "Progress": snapshot.get("Progress", "N/A"),
                            "Encrypted": "Yes" if snapshot.get("Encrypted") else "No",
                            "Description": snapshot.get("Description", "N/A")[:100] if snapshot.get("Description") else "N/A",
                            "MonthlyCost": f"${monthly_cost:.2f}",
                            "StartTime": snapshot.get("StartTime", "").strftime("%Y-%m-%d %H:%M:%S") if snapshot.get("StartTime") else "N/A",
                        })

                    # Process ALB/NLB/GLB Load Balancers
                    for lb in lbs_v2:
                        lb_type = lb.get("Type", "application")
                        lb_state = lb.get("State", {}).get("Code", "N/A")

                        # Get AZs
                        azs = [az.get("ZoneName", "") for az in lb.get("AvailabilityZones", [])]

                        # Get security groups (ALB only)
                        sgs = lb.get("SecurityGroups", [])

                        # Calculate cost
                        monthly_cost = calculate_lb_monthly_cost(lb_type)
                        hourly_cost = PRICING.get(f"{lb_type[:3]}b_hourly", PRICING["alb_hourly"])

                        results["load_balancers"].append({
                            "AccountId": account_id,
                            "AccountName": account_name,
                            "Region": region,
                            "LoadBalancerName": lb.get("LoadBalancerName", "N/A"),
                            "LoadBalancerArn": lb.get("LoadBalancerArn", "N/A"),
                            "Type": lb_type.upper(),
                            "Scheme": lb.get("Scheme", "N/A"),
                            "VpcId": lb.get("VpcId", "N/A"),
                            "State": lb_state,
                            "DNSName": lb.get("DNSName", "N/A"),
                            "AvailabilityZones": ", ".join(azs),
                            "SecurityGroups": ", ".join(sgs) if sgs else "N/A",
                            "IpAddressType": lb.get("IpAddressType", "N/A"),
                            "HourlyCost": f"${hourly_cost:.4f}",
                            "MonthlyCost": f"${monthly_cost:.2f}",
                            "CreatedTime": lb.get("CreatedTime", "").strftime("%Y-%m-%d %H:%M:%S") if lb.get("CreatedTime") else "N/A",
                        })

                    # Process Classic Load Balancers
                    for lb in lbs_classic:
                        # Get AZs
                        azs = lb.get("AvailabilityZones", [])

                        # Get security groups
                        sgs = lb.get("SecurityGroups", [])

                        # Calculate cost
                        monthly_cost = calculate_lb_monthly_cost("classic")
                        hourly_cost = PRICING["clb_hourly"]

                        results["load_balancers"].append({
                            "AccountId": account_id,
                            "AccountName": account_name,
                            "Region": region,
                            "LoadBalancerName": lb.get("LoadBalancerName", "N/A"),
                            "LoadBalancerArn": "N/A",
                            "Type": "CLASSIC",
                            "Scheme": lb.get("Scheme", "N/A"),
                            "VpcId": lb.get("VPCId", "N/A"),
                            "State": "active",
                            "DNSName": lb.get("DNSName", "N/A"),
                            "AvailabilityZones": ", ".join(azs),
                            "SecurityGroups": ", ".join(sgs) if sgs else "N/A",
                            "IpAddressType": "ipv4",
                            "HourlyCost": f"${hourly_cost:.4f}",
                            "MonthlyCost": f"${monthly_cost:.2f}",
                            "CreatedTime": lb.get("CreatedTime", "").strftime("%Y-%m-%d %H:%M:%S") if lb.get("CreatedTime") else "N/A",
                        })

                except ClientError as e:
                    if "AccessDenied" in str(e) or "UnauthorizedOperation" in str(e):
                        print(f"  Access denied in {region}")
                    else:
                        print(f"  Error in {region}: {e}")

        except ProfileNotFound:
            print(f"  Profile not found: {profile_name}")
            failed_accounts.add(profile_name)
        except Exception as e:
            print(f"  Error: {e}")
            failed_accounts.add(profile_name)

    results["scan_info"]["accounts_scanned"] = len(scanned_accounts)
    results["scan_info"]["accounts_failed"] = len(failed_accounts)

    return results


def export_to_json(results: dict, filename: str):
    """Export results to JSON file."""
    with open(filename, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"JSON saved to: {filename}")


def export_to_csv(results: dict, prefix: str):
    """Export results to CSV files."""
    # EC2 Instances
    if results.get("instances"):
        instances_file = f"{prefix}_instances.csv"
        with open(instances_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results["instances"][0].keys())
            writer.writeheader()
            writer.writerows(results["instances"])
        print(f"Instances CSV saved to: {instances_file}")

    # EBS Volumes
    if results.get("volumes"):
        volumes_file = f"{prefix}_volumes.csv"
        with open(volumes_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results["volumes"][0].keys())
            writer.writeheader()
            writer.writerows(results["volumes"])
        print(f"Volumes CSV saved to: {volumes_file}")

    # EBS Snapshots
    if results.get("snapshots"):
        snapshots_file = f"{prefix}_snapshots.csv"
        with open(snapshots_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results["snapshots"][0].keys())
            writer.writeheader()
            writer.writerows(results["snapshots"])
        print(f"Snapshots CSV saved to: {snapshots_file}")

    # Load Balancers
    if results.get("load_balancers"):
        lbs_file = f"{prefix}_load_balancers.csv"
        with open(lbs_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results["load_balancers"][0].keys())
            writer.writeheader()
            writer.writerows(results["load_balancers"])
        print(f"Load Balancers CSV saved to: {lbs_file}")



def export_to_html(results: dict, filename: str):
    """Export results to interactive HTML report."""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS EC2 Scan Report</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            color: #232f3e;
            border-bottom: 3px solid #ff9900;
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
            color: #232f3e;
        }
        .summary-item .label {
            font-size: 12px;
            color: #666;
        }
        .cost-summary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 15px 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            color: white;
        }
        .cost-summary strong {
            font-size: 14px;
            display: block;
            margin-bottom: 10px;
        }
        .cost-grid {
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
            align-items: center;
        }
        .cost-item {
            text-align: center;
        }
        .cost-item .cost-value {
            font-size: 20px;
            font-weight: bold;
        }
        .cost-item .cost-label {
            font-size: 11px;
            opacity: 0.9;
        }
        .cost-total {
            margin-left: auto;
            text-align: right;
            border-left: 2px solid rgba(255,255,255,0.3);
            padding-left: 30px;
        }
        .cost-total .cost-value {
            font-size: 28px;
            font-weight: bold;
        }
        .cost-total .cost-label {
            font-size: 12px;
            opacity: 0.9;
        }
        .cost-note {
            margin-top: 12px;
            padding-top: 10px;
            border-top: 1px solid rgba(255,255,255,0.2);
            font-size: 11px;
            opacity: 0.9;
            line-height: 1.4;
        }
        .cost-note strong {
            display: block;
            margin-bottom: 4px;
            font-size: 11px;
        }
        .tabs {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            margin-bottom: 0;
            background-color: #232f3e;
            padding: 10px 10px 0 10px;
            border-radius: 5px 5px 0 0;
        }
        .tab {
            padding: 10px 20px;
            background-color: #37475a;
            color: #fff;
            border: none;
            cursor: pointer;
            border-radius: 5px 5px 0 0;
            font-size: 13px;
        }
        .tab:hover { background-color: #4a5c6f; }
        .tab.active { background-color: #fff; color: #232f3e; }
        .tab-content {
            display: none;
            background-color: #fff;
            padding: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-radius: 0 0 5px 5px;
        }
        .tab-content.active { display: block; }
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
        .filter-group input { width: 180px; }
        .filter-group select { min-width: 150px; }
        .btn-clear {
            padding: 8px 16px;
            background-color: #232f3e;
            color: #fff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            margin-top: 18px;
        }
        .btn-clear:hover { background-color: #37475a; }
        .table-container {
            overflow-x: auto;
            max-height: 70vh;
            overflow-y: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            table-layout: auto;
        }
        th {
            background-color: #232f3e;
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
            background: rgba(255, 153, 0, 0.5);
        }
        th:hover { background-color: #37475a; }
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
        .status-running, .status-available, .status-attached, .status-active { color: #1d8102; font-weight: bold; }
        .status-pending { color: #ff9900; font-weight: bold; }
        .status-stopped, .status-deleted, .status-detached, .status-failed { color: #d13212; font-weight: bold; }
        .status-in-use { color: #1d8102; font-weight: bold; }
        .yes { color: #1d8102; }
        .no { color: #879596; }
        .timestamp { color: #879596; font-size: 12px; margin-bottom: 20px; }
        .result-count { color: #666; font-size: 13px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <h1>AWS EC2 Scan Report</h1>
    <p class="timestamp">Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>

    <div class="summary">
        <strong>Summary</strong>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="count">""" + str(results["scan_info"]["accounts_scanned"]) + """</div>
                <div class="label">Accounts</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("instances", []))) + """</div>
                <div class="label">EC2 Instances</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("volumes", []))) + """</div>
                <div class="label">EBS Volumes</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("snapshots", []))) + """</div>
                <div class="label">EBS Snapshots</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("load_balancers", []))) + """</div>
                <div class="label">Load Balancers</div>
            </div>
        </div>
    </div>

    <div class="cost-summary">
        <strong>Estimated Monthly Costs</strong>
        <div class="cost-grid">
            <div class="cost-item">
                <div class="cost-value" id="instanceCost">$0.00</div>
                <div class="cost-label">EC2 Instances</div>
            </div>
            <div class="cost-item">
                <div class="cost-value" id="volumeCost">$0.00</div>
                <div class="cost-label">EBS Volumes</div>
            </div>
            <div class="cost-item">
                <div class="cost-value" id="snapshotCost">$0.00</div>
                <div class="cost-label">EBS Snapshots</div>
            </div>
            <div class="cost-item">
                <div class="cost-value" id="lbCost">$0.00</div>
                <div class="cost-label">Load Balancers</div>
            </div>
            <div class="cost-item cost-total">
                <div class="cost-value" id="totalCost">$0.00</div>
                <div class="cost-label">Total Monthly</div>
            </div>
        </div>
        <div class="cost-note">
            <strong>Note:</strong> Costs shown are on-demand pricing (us-east-1) based on AWS Price Calculator. Actual costs may be lower if using Reserved Instances, Savings Plans, Spot Instances, or other discounts. EC2 costs are for running instances only. EBS costs are storage only. LB costs are base hourly charges; LCU/data processing charges not included.
        </div>
    </div>

    <div class="tabs">
        <button class="tab active" onclick="showTab('instances')">Instances (""" + str(len(results.get("instances", []))) + """)</button>
        <button class="tab" onclick="showTab('volumes')">EBS Volumes (""" + str(len(results.get("volumes", []))) + """)</button>
        <button class="tab" onclick="showTab('snapshots')">Snapshots (""" + str(len(results.get("snapshots", []))) + """)</button>
        <button class="tab" onclick="showTab('lbs')">Load Balancers (""" + str(len(results.get("load_balancers", []))) + """)</button>
    </div>
"""

    # EC2 Instances Tab
    html += """
    <div id="instances" class="tab-content active">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="instancesSearch" placeholder="Search..." onkeyup="filterTable('instances')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="instancesAccount" onchange="filterTable('instances')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="instancesRegion" onchange="filterTable('instances')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>State</label>
                <select id="instancesState" onchange="filterTable('instances')">
                    <option value="">All</option>
                    <option value="running">Running</option>
                    <option value="stopped">Stopped</option>
                    <option value="pending">Pending</option>
                    <option value="terminated">Terminated</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Platform</label>
                <select id="instancesPlatform" onchange="filterTable('instances')">
                    <option value="">All</option>
                    <option value="Linux">Linux</option>
                    <option value="Windows">Windows</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('instances')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="instancesCount">0</span> of """ + str(len(results.get("instances", []))) + """ instances</div>
        <div class="table-container">
        <table id="instancesTable">
            <thead>
                <tr>
                    <th>Account ID<span class="sort-icon"></span></th>
                    <th>Account Name<span class="sort-icon"></span></th>
                    <th>Region<span class="sort-icon"></span></th>
                    <th>Instance ID<span class="sort-icon"></span></th>
                    <th>Name<span class="sort-icon"></span></th>
                    <th>Type<span class="sort-icon"></span></th>
                    <th>Platform<span class="sort-icon"></span></th>
                    <th>State<span class="sort-icon"></span></th>
                    <th>Managed By<span class="sort-icon"></span></th>
                    <th>Schedule<span class="sort-icon"></span></th>
                    <th>VPC ID<span class="sort-icon"></span></th>
                    <th>Private IP<span class="sort-icon"></span></th>
                    <th>Public IP<span class="sort-icon"></span></th>
                    <th>Key Name<span class="sort-icon"></span></th>
                    <th>IAM Role<span class="sort-icon"></span></th>
                    <th>EBS Volumes<span class="sort-icon"></span></th>
                    <th>Security Groups<span class="sort-icon"></span></th>
                    <th>Hourly Cost<span class="sort-icon"></span></th>
                    <th>Monthly Cost<span class="sort-icon"></span></th>
                    <th>Launch Time<span class="sort-icon"></span></th>
                </tr>
            </thead>
            <tbody>
"""
    for instance in results.get("instances", []):
        state = instance["State"]
        if state == "running":
            state_class = "status-running"
        elif state == "stopped":
            state_class = "status-stopped"
        elif state == "pending":
            state_class = "status-pending"
        else:
            state_class = ""
        managed_by = instance['ManagedBy']
        managed_class = "yes" if managed_by != "No" else "no"
        html += f"""                <tr>
                    <td>{instance['AccountId']}</td>
                    <td>{instance['AccountName']}</td>
                    <td>{instance['Region']}</td>
                    <td>{instance['InstanceId']}</td>
                    <td>{instance['InstanceName']}</td>
                    <td>{instance['InstanceType']}</td>
                    <td>{instance['Platform']}</td>
                    <td class="{state_class}">{instance['State']}</td>
                    <td class="{managed_class}">{managed_by}</td>
                    <td>{instance['Schedule']}</td>
                    <td>{instance['VpcId']}</td>
                    <td>{instance['PrivateIp']}</td>
                    <td>{instance['PublicIp']}</td>
                    <td>{instance['KeyName']}</td>
                    <td>{instance['IamRole']}</td>
                    <td>{instance['EbsVolumes']}</td>
                    <td>{instance['SecurityGroups']}</td>
                    <td>{instance['HourlyCost']}</td>
                    <td>{instance['MonthlyCost']}</td>
                    <td>{instance['LaunchTime']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # EBS Volumes Tab
    html += """
    <div id="volumes" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="volumesSearch" placeholder="Search..." onkeyup="filterTable('volumes')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="volumesAccount" onchange="filterTable('volumes')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="volumesRegion" onchange="filterTable('volumes')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Type</label>
                <select id="volumesType" onchange="filterTable('volumes')">
                    <option value="">All Types</option>
                    <option value="gp2">gp2</option>
                    <option value="gp3">gp3</option>
                    <option value="io1">io1</option>
                    <option value="io2">io2</option>
                    <option value="st1">st1</option>
                    <option value="sc1">sc1</option>
                    <option value="standard">standard</option>
                </select>
            </div>
            <div class="filter-group">
                <label>State</label>
                <select id="volumesState" onchange="filterTable('volumes')">
                    <option value="">All</option>
                    <option value="available">Available</option>
                    <option value="in-use">In Use</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Encrypted</label>
                <select id="volumesEncrypted" onchange="filterTable('volumes')">
                    <option value="">All</option>
                    <option value="Yes">Yes</option>
                    <option value="No">No</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('volumes')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="volumesCount">0</span> of """ + str(len(results.get("volumes", []))) + """ volumes</div>
        <div class="table-container">
        <table id="volumesTable">
            <thead>
                <tr>
                    <th>Account ID<span class="sort-icon"></span></th>
                    <th>Account Name<span class="sort-icon"></span></th>
                    <th>Region<span class="sort-icon"></span></th>
                    <th>Volume ID<span class="sort-icon"></span></th>
                    <th>Name<span class="sort-icon"></span></th>
                    <th>Type<span class="sort-icon"></span></th>
                    <th>Size (GB)<span class="sort-icon"></span></th>
                    <th>State<span class="sort-icon"></span></th>
                    <th>IOPS<span class="sort-icon"></span></th>
                    <th>Throughput<span class="sort-icon"></span></th>
                    <th>Encrypted<span class="sort-icon"></span></th>
                    <th>Attached To<span class="sort-icon"></span></th>
                    <th>Device<span class="sort-icon"></span></th>
                    <th>AZ<span class="sort-icon"></span></th>
                    <th>Monthly Cost<span class="sort-icon"></span></th>
                    <th>Created<span class="sort-icon"></span></th>
                </tr>
            </thead>
            <tbody>
"""
    for vol in results.get("volumes", []):
        state = vol["State"]
        if state == "available":
            state_class = "status-available"
        elif state == "in-use":
            state_class = "status-in-use"
        else:
            state_class = ""
        encrypted_class = "yes" if vol["Encrypted"] == "Yes" else "no"
        html += f"""                <tr>
                    <td>{vol['AccountId']}</td>
                    <td>{vol['AccountName']}</td>
                    <td>{vol['Region']}</td>
                    <td>{vol['VolumeId']}</td>
                    <td>{vol['VolumeName']}</td>
                    <td>{vol['VolumeType']}</td>
                    <td>{vol['Size']}</td>
                    <td class="{state_class}">{vol['State']}</td>
                    <td>{vol['Iops']}</td>
                    <td>{vol['Throughput']}</td>
                    <td class="{encrypted_class}">{vol['Encrypted']}</td>
                    <td>{vol['AttachedTo']}</td>
                    <td>{vol['Device']}</td>
                    <td>{vol['AvailabilityZone']}</td>
                    <td>{vol['MonthlyCost']}</td>
                    <td>{vol['CreateTime']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # EBS Snapshots Tab
    html += """
    <div id="snapshots" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="snapshotsSearch" placeholder="Search..." onkeyup="filterTable('snapshots')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="snapshotsAccount" onchange="filterTable('snapshots')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="snapshotsRegion" onchange="filterTable('snapshots')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>State</label>
                <select id="snapshotsState" onchange="filterTable('snapshots')">
                    <option value="">All</option>
                    <option value="completed">Completed</option>
                    <option value="pending">Pending</option>
                    <option value="error">Error</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Encrypted</label>
                <select id="snapshotsEncrypted" onchange="filterTable('snapshots')">
                    <option value="">All</option>
                    <option value="Yes">Yes</option>
                    <option value="No">No</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('snapshots')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="snapshotsCount">0</span> of """ + str(len(results.get("snapshots", []))) + """ snapshots</div>
        <div class="table-container">
        <table id="snapshotsTable">
            <thead>
                <tr>
                    <th>Account ID<span class="sort-icon"></span></th>
                    <th>Account Name<span class="sort-icon"></span></th>
                    <th>Region<span class="sort-icon"></span></th>
                    <th>Snapshot ID<span class="sort-icon"></span></th>
                    <th>Name<span class="sort-icon"></span></th>
                    <th>Volume ID<span class="sort-icon"></span></th>
                    <th>Size (GB)<span class="sort-icon"></span></th>
                    <th>State<span class="sort-icon"></span></th>
                    <th>Progress<span class="sort-icon"></span></th>
                    <th>Encrypted<span class="sort-icon"></span></th>
                    <th>Description<span class="sort-icon"></span></th>
                    <th>Monthly Cost<span class="sort-icon"></span></th>
                    <th>Start Time<span class="sort-icon"></span></th>
                </tr>
            </thead>
            <tbody>
"""
    for snap in results.get("snapshots", []):
        state = snap["State"]
        if state == "completed":
            state_class = "status-available"
        elif state == "pending":
            state_class = "status-pending"
        else:
            state_class = ""
        encrypted_class = "yes" if snap["Encrypted"] == "Yes" else "no"
        html += f"""                <tr>
                    <td>{snap['AccountId']}</td>
                    <td>{snap['AccountName']}</td>
                    <td>{snap['Region']}</td>
                    <td>{snap['SnapshotId']}</td>
                    <td>{snap['SnapshotName']}</td>
                    <td>{snap['VolumeId']}</td>
                    <td>{snap['VolumeSize']}</td>
                    <td class="{state_class}">{snap['State']}</td>
                    <td>{snap['Progress']}</td>
                    <td class="{encrypted_class}">{snap['Encrypted']}</td>
                    <td>{snap['Description']}</td>
                    <td>{snap['MonthlyCost']}</td>
                    <td>{snap['StartTime']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # Load Balancers Tab
    html += """
    <div id="lbs" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="lbsSearch" placeholder="Search..." onkeyup="filterTable('lbs')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="lbsAccount" onchange="filterTable('lbs')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="lbsRegion" onchange="filterTable('lbs')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Type</label>
                <select id="lbsType" onchange="filterTable('lbs')">
                    <option value="">All Types</option>
                    <option value="APPLICATION">ALB</option>
                    <option value="NETWORK">NLB</option>
                    <option value="GATEWAY">GLB</option>
                    <option value="CLASSIC">Classic</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Scheme</label>
                <select id="lbsScheme" onchange="filterTable('lbs')">
                    <option value="">All</option>
                    <option value="internet-facing">Internet-facing</option>
                    <option value="internal">Internal</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('lbs')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="lbsCount">0</span> of """ + str(len(results.get("load_balancers", []))) + """ load balancers</div>
        <div class="table-container">
        <table id="lbsTable">
            <thead>
                <tr>
                    <th>Account ID<span class="sort-icon"></span></th>
                    <th>Account Name<span class="sort-icon"></span></th>
                    <th>Region<span class="sort-icon"></span></th>
                    <th>Name<span class="sort-icon"></span></th>
                    <th>Type<span class="sort-icon"></span></th>
                    <th>Scheme<span class="sort-icon"></span></th>
                    <th>State<span class="sort-icon"></span></th>
                    <th>VPC ID<span class="sort-icon"></span></th>
                    <th>DNS Name<span class="sort-icon"></span></th>
                    <th>Availability Zones<span class="sort-icon"></span></th>
                    <th>Security Groups<span class="sort-icon"></span></th>
                    <th>Hourly Cost<span class="sort-icon"></span></th>
                    <th>Monthly Cost<span class="sort-icon"></span></th>
                    <th>Created<span class="sort-icon"></span></th>
                </tr>
            </thead>
            <tbody>
"""
    for lb in results.get("load_balancers", []):
        state = lb["State"]
        if state == "active":
            state_class = "status-active"
        else:
            state_class = ""
        html += f"""                <tr>
                    <td>{lb['AccountId']}</td>
                    <td>{lb['AccountName']}</td>
                    <td>{lb['Region']}</td>
                    <td>{lb['LoadBalancerName']}</td>
                    <td>{lb['Type']}</td>
                    <td>{lb['Scheme']}</td>
                    <td class="{state_class}">{lb['State']}</td>
                    <td>{lb['VpcId']}</td>
                    <td>{lb['DNSName']}</td>
                    <td>{lb['AvailabilityZones']}</td>
                    <td>{lb['SecurityGroups']}</td>
                    <td>{lb['HourlyCost']}</td>
                    <td>{lb['MonthlyCost']}</td>
                    <td>{lb['CreatedTime']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # JavaScript
    html += """
<script>
// Calculate and update total costs from visible rows
function updateCosts() {
    let instanceTotal = 0;
    let volumeTotal = 0;
    let snapshotTotal = 0;
    let lbTotal = 0;

    // Calculate EC2 Instance costs (MonthlyCost is column 18)
    const instancesTable = document.getElementById('instancesTable');
    if (instancesTable) {
        const rows = instancesTable.querySelectorAll('tbody tr');
        rows.forEach(row => {
            if (!row.classList.contains('hidden')) {
                const costCell = row.cells[18];
                if (costCell) {
                    const cost = parseFloat(costCell.textContent.replace('$', '').replace(',', '').replace('N/A', '0')) || 0;
                    instanceTotal += cost;
                }
            }
        });
    }

    // Calculate EBS Volume costs (MonthlyCost is column 14)
    const volumesTable = document.getElementById('volumesTable');
    if (volumesTable) {
        const rows = volumesTable.querySelectorAll('tbody tr');
        rows.forEach(row => {
            if (!row.classList.contains('hidden')) {
                const costCell = row.cells[14];
                if (costCell) {
                    const cost = parseFloat(costCell.textContent.replace('$', '').replace(',', '')) || 0;
                    volumeTotal += cost;
                }
            }
        });
    }

    // Calculate Snapshot costs (MonthlyCost is column 11)
    const snapshotsTable = document.getElementById('snapshotsTable');
    if (snapshotsTable) {
        const rows = snapshotsTable.querySelectorAll('tbody tr');
        rows.forEach(row => {
            if (!row.classList.contains('hidden')) {
                const costCell = row.cells[11];
                if (costCell) {
                    const cost = parseFloat(costCell.textContent.replace('$', '').replace(',', '')) || 0;
                    snapshotTotal += cost;
                }
            }
        });
    }

    // Calculate Load Balancer costs (MonthlyCost is column 12)
    const lbsTable = document.getElementById('lbsTable');
    if (lbsTable) {
        const rows = lbsTable.querySelectorAll('tbody tr');
        rows.forEach(row => {
            if (!row.classList.contains('hidden')) {
                const costCell = row.cells[12];
                if (costCell) {
                    const cost = parseFloat(costCell.textContent.replace('$', '').replace(',', '')) || 0;
                    lbTotal += cost;
                }
            }
        });
    }

    // Update the display with formatted numbers
    const formatCost = (cost) => '$' + cost.toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2});
    const totalCost = instanceTotal + volumeTotal + snapshotTotal + lbTotal;
    document.getElementById('instanceCost').textContent = formatCost(instanceTotal);
    document.getElementById('volumeCost').textContent = formatCost(volumeTotal);
    document.getElementById('snapshotCost').textContent = formatCost(snapshotTotal);
    document.getElementById('lbCost').textContent = formatCost(lbTotal);
    document.getElementById('totalCost').textContent = formatCost(totalCost);
}

function showTab(tabId) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.querySelector(`[onclick="showTab('${tabId}')"]`).classList.add('active');
    document.getElementById(tabId).classList.add('active');
    filterTable(tabId);
}

function populateFilters() {
    const tabs = ['instances', 'volumes', 'snapshots', 'lbs'];
    tabs.forEach(tab => {
        const table = document.getElementById(tab + 'Table');
        if (!table) return;

        const accountSelect = document.getElementById(tab + 'Account');
        const regionSelect = document.getElementById(tab + 'Region');

        const accounts = new Set();
        const regions = new Set();

        table.querySelectorAll('tbody tr').forEach(row => {
            accounts.add(row.cells[1].textContent);
            regions.add(row.cells[2].textContent);
        });

        Array.from(accounts).sort().forEach(account => {
            const option = document.createElement('option');
            option.value = account;
            option.textContent = account;
            accountSelect.appendChild(option);
        });

        Array.from(regions).sort().forEach(region => {
            const option = document.createElement('option');
            option.value = region;
            option.textContent = region;
            regionSelect.appendChild(option);
        });
    });
}

function filterTable(tabId) {
    const table = document.getElementById(tabId + 'Table');
    if (!table) return;

    const searchInput = document.getElementById(tabId + 'Search');
    const accountSelect = document.getElementById(tabId + 'Account');
    const regionSelect = document.getElementById(tabId + 'Region');

    const search = searchInput ? searchInput.value.toLowerCase() : '';
    const account = accountSelect ? accountSelect.value : '';
    const region = regionSelect ? regionSelect.value : '';

    // Get extra filters based on tab
    let extraFilter = '';
    let extraFilter2 = '';
    if (tabId === 'instances') {
        const stateSelect = document.getElementById('instancesState');
        const platformSelect = document.getElementById('instancesPlatform');
        extraFilter = stateSelect ? stateSelect.value : '';
        extraFilter2 = platformSelect ? platformSelect.value : '';
    } else if (tabId === 'volumes') {
        const typeSelect = document.getElementById('volumesType');
        const stateSelect = document.getElementById('volumesState');
        const encryptedSelect = document.getElementById('volumesEncrypted');
        extraFilter = typeSelect ? typeSelect.value : '';
        extraFilter2 = stateSelect ? stateSelect.value : '';
    } else if (tabId === 'snapshots') {
        const stateSelect = document.getElementById('snapshotsState');
        const encryptedSelect = document.getElementById('snapshotsEncrypted');
        extraFilter = stateSelect ? stateSelect.value : '';
        extraFilter2 = encryptedSelect ? encryptedSelect.value : '';
    } else if (tabId === 'lbs') {
        const typeSelect = document.getElementById('lbsType');
        const schemeSelect = document.getElementById('lbsScheme');
        extraFilter = typeSelect ? typeSelect.value : '';
        extraFilter2 = schemeSelect ? schemeSelect.value : '';
    }

    let visible = 0;
    const rows = table.querySelectorAll('tbody tr');

    rows.forEach(row => {
        const rowText = row.textContent.toLowerCase();
        const rowAccount = row.cells[1].textContent;
        const rowRegion = row.cells[2].textContent;

        let show = true;

        if (search && !rowText.includes(search)) show = false;
        if (account && rowAccount !== account) show = false;
        if (region && rowRegion !== region) show = false;

        // Extra filters
        if (extraFilter) {
            if (tabId === 'instances') {
                const state = row.cells[7].textContent;
                if (state !== extraFilter) show = false;
            } else if (tabId === 'volumes') {
                const type = row.cells[5].textContent;
                if (type !== extraFilter) show = false;
            } else if (tabId === 'snapshots') {
                const state = row.cells[7].textContent;
                if (state !== extraFilter) show = false;
            } else if (tabId === 'lbs') {
                const type = row.cells[4].textContent;
                if (type !== extraFilter) show = false;
            }
        }

        // Second extra filters
        if (extraFilter2) {
            if (tabId === 'instances') {
                const platform = row.cells[6].textContent;
                if (platform !== extraFilter2) show = false;
            } else if (tabId === 'volumes') {
                const state = row.cells[7].textContent;
                if (state !== extraFilter2) show = false;
            } else if (tabId === 'snapshots') {
                const encrypted = row.cells[9].textContent;
                if (encrypted !== extraFilter2) show = false;
            } else if (tabId === 'lbs') {
                const scheme = row.cells[5].textContent;
                if (scheme !== extraFilter2) show = false;
            }
        }

        // Third extra filter for volumes (encrypted)
        if (tabId === 'volumes') {
            const encryptedSelect = document.getElementById('volumesEncrypted');
            const encryptedFilter = encryptedSelect ? encryptedSelect.value : '';
            if (encryptedFilter) {
                const encrypted = row.cells[10].textContent;
                if (encrypted !== encryptedFilter) show = false;
            }
        }

        row.classList.toggle('hidden', !show);
        if (show) visible++;
    });

    const countSpan = document.getElementById(tabId + 'Count');
    if (countSpan) countSpan.textContent = visible;

    // Update cost summary
    updateCosts();
}

function clearFilters(tabId) {
    const searchInput = document.getElementById(tabId + 'Search');
    const accountSelect = document.getElementById(tabId + 'Account');
    const regionSelect = document.getElementById(tabId + 'Region');

    if (searchInput) searchInput.value = '';
    if (accountSelect) accountSelect.value = '';
    if (regionSelect) regionSelect.value = '';

    // Clear extra filters
    if (tabId === 'instances') {
        document.getElementById('instancesState').value = '';
        document.getElementById('instancesPlatform').value = '';
    } else if (tabId === 'volumes') {
        document.getElementById('volumesType').value = '';
        document.getElementById('volumesState').value = '';
        document.getElementById('volumesEncrypted').value = '';
    } else if (tabId === 'snapshots') {
        document.getElementById('snapshotsState').value = '';
        document.getElementById('snapshotsEncrypted').value = '';
    } else if (tabId === 'lbs') {
        document.getElementById('lbsType').value = '';
        document.getElementById('lbsScheme').value = '';
    }

    filterTable(tabId);
}

// Sorting functionality
function sortTable(tableId, colIndex) {
    const table = document.getElementById(tableId);
    if (!table) return;

    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const th = table.querySelectorAll('th')[colIndex];

    // Determine sort direction
    const isAsc = th.classList.contains('sort-asc');
    const isDesc = th.classList.contains('sort-desc');

    // Clear all sort classes from this table's headers
    table.querySelectorAll('th').forEach(header => {
        header.classList.remove('sort-asc', 'sort-desc');
    });

    // Set new sort direction
    let direction;
    if (!isAsc && !isDesc) {
        direction = 'asc';
        th.classList.add('sort-asc');
    } else if (isAsc) {
        direction = 'desc';
        th.classList.add('sort-desc');
    } else {
        direction = 'asc';
        th.classList.add('sort-asc');
    }

    // Sort rows
    rows.sort((a, b) => {
        let aVal = a.cells[colIndex].textContent.trim();
        let bVal = b.cells[colIndex].textContent.trim();

        // Try to parse as numbers (including currency)
        const aNum = parseFloat(aVal.replace(/[$,]/g, ''));
        const bNum = parseFloat(bVal.replace(/[$,]/g, ''));

        if (!isNaN(aNum) && !isNaN(bNum)) {
            return direction === 'asc' ? aNum - bNum : bNum - aNum;
        }

        // String comparison
        return direction === 'asc'
            ? aVal.localeCompare(bVal)
            : bVal.localeCompare(aVal);
    });

    // Re-append sorted rows
    rows.forEach(row => tbody.appendChild(row));
}

// Column resize functionality
function initResizableColumns() {
    document.querySelectorAll('table').forEach(table => {
        const headerCells = table.querySelectorAll('th');

        headerCells.forEach(th => {
            // Add resize handle
            const handle = document.createElement('div');
            handle.className = 'resize-handle';
            th.appendChild(handle);

            let startX, startWidth;

            handle.addEventListener('mousedown', function(e) {
                e.stopPropagation(); // Prevent sorting
                startX = e.pageX;
                startWidth = th.offsetWidth;

                const onMouseMove = function(e) {
                    const width = startWidth + (e.pageX - startX);
                    if (width >= 60) {
                        th.style.width = width + 'px';
                        th.style.minWidth = width + 'px';
                    }
                };

                const onMouseUp = function() {
                    document.removeEventListener('mousemove', onMouseMove);
                    document.removeEventListener('mouseup', onMouseUp);
                };

                document.addEventListener('mousemove', onMouseMove);
                document.addEventListener('mouseup', onMouseUp);
            });
        });
    });
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    populateFilters();

    // Add click handlers for sorting (ignore clicks on resize handle)
    document.querySelectorAll('table').forEach(table => {
        table.querySelectorAll('th').forEach((th, index) => {
            th.addEventListener('click', (e) => {
                if (!e.target.classList.contains('resize-handle')) {
                    sortTable(table.id, index);
                }
            });
        });
    });

    // Initialize resizable columns
    initResizableColumns();

    // Initial filter and count
    ['instances', 'volumes', 'snapshots', 'lbs'].forEach(tab => {
        filterTable(tab);
    });

    // Initial cost calculation
    updateCosts();
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
    print(f"Profiles attempted: {results['scan_info']['profiles_attempted']}")
    print(f"Accounts scanned: {results['scan_info']['accounts_scanned']}")
    print(f"Accounts failed: {results['scan_info']['accounts_failed']}")
    print(f"Regions scanned: {', '.join(results['scan_info']['regions'])}")
    print()
    print("Resources Found:")
    print(f"  EC2 Instances: {len(results.get('instances', [])):,}")
    print(f"  EBS Volumes: {len(results.get('volumes', [])):,}")
    print(f"  EBS Snapshots: {len(results.get('snapshots', [])):,}")
    print(f"  Load Balancers: {len(results.get('load_balancers', [])):,}")

    # Calculate total costs
    instance_cost = sum(float(i['MonthlyCost'].replace('$', '').replace(',', '').replace('N/A', '0')) for i in results.get('instances', []))
    volume_cost = sum(float(v['MonthlyCost'].replace('$', '').replace(',', '')) for v in results.get('volumes', []))
    snapshot_cost = sum(float(s['MonthlyCost'].replace('$', '').replace(',', '')) for s in results.get('snapshots', []))
    lb_cost = sum(float(lb['MonthlyCost'].replace('$', '').replace(',', '')) for lb in results.get('load_balancers', []))
    total_cost = instance_cost + volume_cost + snapshot_cost + lb_cost

    print()
    print("Estimated Monthly Costs:")
    print(f"  EC2 Instances: ${instance_cost:,.2f}")
    print(f"  EBS Volumes: ${volume_cost:,.2f}")
    print(f"  EBS Snapshots: ${snapshot_cost:,.2f}")
    print(f"  Load Balancers: ${lb_cost:,.2f}")
    print(f"  Total: ${total_cost:,.2f}")
    print("  (Note: Instance costs are for running instances only, on-demand us-east-1 pricing)")


def main():
    parser = argparse.ArgumentParser(
        description="Scan EC2 resources across multiple AWS accounts"
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
        help="Export to CSV files (prefix)"
    )
    parser.add_argument(
        "--html",
        help="Export to HTML file"
    )
    parser.add_argument(
        "--profile",
        help="Scan specific profile only"
    )
    parser.add_argument(
        "--profile-pattern",
        default=".admin",
        help="Profile name pattern to match (default: .admin)"
    )
    parser.add_argument(
        "--regions",
        default=",".join(DEFAULT_REGIONS),
        help=f"Comma-separated regions (default: {','.join(DEFAULT_REGIONS)})"
    )

    args = parser.parse_args()

    # Get profiles to scan
    if args.profile:
        # Get account name for single profile
        all_profiles = get_aws_profiles("")
        account_name = all_profiles.get(args.profile, args.profile)
        profiles = {args.profile: account_name}
    else:
        profiles = get_aws_profiles(args.profile_pattern)

    if not profiles:
        print("No profiles found matching the pattern")
        sys.exit(1)

    regions = [r.strip() for r in args.regions.split(",")]

    print(f"Found {len(profiles)} profile(s) to scan")
    print(f"Regions: {', '.join(regions)}")
    print("=" * 60)

    # Scan all accounts
    results = scan_accounts(profiles, regions, args.verbose)

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
