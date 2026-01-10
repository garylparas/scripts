#!/usr/bin/env python3
"""
AWS RDS Scanner

Scans RDS resources (DB instances, Aurora clusters, snapshots) across multiple
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

from rds_pricing import (
    RDS_PRICING, AURORA_PRICING, STORAGE_PRICING, HOURS_PER_MONTH,
    get_rds_hourly_cost, get_rds_monthly_cost, get_storage_monthly_cost,
    SERVERLESS_V2_ACU_PRICE
)


DEFAULT_REGIONS = ["us-east-1", "us-west-2"]


def get_aws_profiles(pattern: str = ".admin") -> dict:
    """Get all AWS profiles matching the pattern from ~/.aws/config.

    Returns:
        dict: {profile_name: account_name}
    """
    config_path = Path.home() / ".aws" / "config"
    if not config_path.exists():
        print(f"AWS config file not found: {config_path}")
        return {}

    config = configparser.ConfigParser()
    config.read(config_path)

    profiles = {}
    for section in config.sections():
        if section.startswith("profile "):
            profile_name = section.replace("profile ", "")
            if pattern in profile_name:
                # Try to extract account name from sso_account_id or profile name
                account_name = profile_name.replace(pattern, "").strip("-._")
                if "sso_account_id" in config[section]:
                    # Use profile name prefix as account name
                    pass
                profiles[profile_name] = account_name

    return profiles


def get_boto3_session(profile_name: str) -> Optional[boto3.Session]:
    """Create a boto3 session for the given profile."""
    try:
        session = boto3.Session(profile_name=profile_name)
        # Test the session by getting caller identity
        sts = session.client("sts")
        sts.get_caller_identity()
        return session
    except (ProfileNotFound, NoCredentialsError, TokenRetrievalError, SSOTokenLoadError) as e:
        return None
    except ClientError as e:
        if "ExpiredToken" in str(e) or "InvalidIdentityToken" in str(e):
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


def get_db_instances(rds_client) -> list:
    """Get all RDS DB instances."""
    instances = []
    try:
        paginator = rds_client.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            instances.extend(page.get("DBInstances", []))
    except ClientError as e:
        if "AccessDenied" in str(e):
            return None
        raise
    return instances


def get_db_clusters(rds_client) -> list:
    """Get all Aurora DB clusters."""
    clusters = []
    try:
        paginator = rds_client.get_paginator("describe_db_clusters")
        for page in paginator.paginate():
            clusters.extend(page.get("DBClusters", []))
    except ClientError as e:
        if "AccessDenied" in str(e):
            return None
        raise
    return clusters


def get_db_snapshots(rds_client, account_id: str) -> list:
    """Get all manual DB snapshots (owned by this account)."""
    snapshots = []
    try:
        paginator = rds_client.get_paginator("describe_db_snapshots")
        for page in paginator.paginate(SnapshotType="manual"):
            snapshots.extend(page.get("DBSnapshots", []))
    except ClientError as e:
        if "AccessDenied" in str(e):
            return None
        raise
    return snapshots


def get_cluster_snapshots(rds_client, account_id: str) -> list:
    """Get all manual Aurora cluster snapshots."""
    snapshots = []
    try:
        paginator = rds_client.get_paginator("describe_db_cluster_snapshots")
        for page in paginator.paginate(SnapshotType="manual"):
            snapshots.extend(page.get("DBClusterSnapshots", []))
    except ClientError as e:
        if "AccessDenied" in str(e):
            return None
        raise
    return snapshots


def get_reserved_db_instances(rds_client) -> list:
    """Get all reserved DB instances."""
    reserved = []
    try:
        paginator = rds_client.get_paginator("describe_reserved_db_instances")
        for page in paginator.paginate():
            reserved.extend(page.get("ReservedDBInstances", []))
    except ClientError as e:
        if "AccessDenied" in str(e):
            return None
        raise
    return reserved


def scan_accounts(profiles: dict, regions: list, verbose: bool = False) -> dict:
    """Scan RDS resources across all profiles and regions."""
    results = {
        "instances": [],
        "clusters": [],
        "snapshots": [],
        "cluster_snapshots": [],
        "reserved": [],
        "scan_info": {
            "profiles_attempted": len(profiles),
            "accounts_scanned": 0,
            "accounts_failed": 0,
            "regions": regions,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    }

    scanned_accounts = set()
    failed_accounts = set()

    for idx, (profile_name, account_name) in enumerate(profiles.items(), 1):
        print(f"[{idx}/{len(profiles)}] Scanning profile: {profile_name} ({account_name})")

        session = get_boto3_session(profile_name)
        if not session:
            print(f"  Skipping - credentials expired or unavailable")
            failed_accounts.add(profile_name)
            continue

        # Get account ID
        try:
            sts = session.client("sts")
            account_id = sts.get_caller_identity()["Account"]
        except Exception as e:
            print(f"  Skipping - could not get account ID: {e}")
            failed_accounts.add(profile_name)
            continue

        account_scanned = False

        for region in regions:
            if verbose:
                print(f"  Scanning region: {region}")

            try:
                rds_client = session.client("rds", region_name=region)

                # Get DB Instances
                instances = get_db_instances(rds_client)
                if instances is None:
                    if verbose:
                        print(f"    Access denied to RDS in {region}")
                    continue

                # Get Aurora Clusters
                clusters = get_db_clusters(rds_client)

                # Get DB Snapshots (manual only)
                snapshots = get_db_snapshots(rds_client, account_id)

                # Get Cluster Snapshots (manual only)
                cluster_snapshots = get_cluster_snapshots(rds_client, account_id)

                # Get Reserved DB Instances
                reserved = get_reserved_db_instances(rds_client)

                account_scanned = True

                # Build map of cluster serverless configs for cost calculation
                cluster_serverless_config = {}
                for cluster in (clusters or []):
                    c_id = cluster.get("DBClusterIdentifier", "")
                    serverless_config = cluster.get("ServerlessV2ScalingConfiguration", {})
                    if serverless_config:
                        cluster_serverless_config[c_id] = {
                            "min_capacity": serverless_config.get("MinCapacity", 0),
                            "max_capacity": serverless_config.get("MaxCapacity", 0),
                        }

                # Process DB Instances (exclude DocumentDB)
                for instance in instances:
                    engine = instance.get("Engine", "N/A")
                    # Skip DocumentDB instances
                    if "docdb" in engine.lower():
                        continue
                    db_id = instance.get("DBInstanceIdentifier", "N/A")
                    instance_class = instance.get("DBInstanceClass", "N/A")
                    engine_version = instance.get("EngineVersion", "N/A")
                    status = instance.get("DBInstanceStatus", "N/A")
                    multi_az = instance.get("MultiAZ", False)
                    storage_type = instance.get("StorageType", "gp2")
                    storage_gb = instance.get("AllocatedStorage", 0)
                    iops = instance.get("Iops", 0)
                    cluster_id = instance.get("DBClusterIdentifier", "")

                    # Calculate costs
                    is_aurora = "aurora" in engine.lower()
                    is_serverless = instance_class.lower() == "db.serverless"

                    if is_serverless and cluster_id and status == "available":
                        # Aurora Serverless v2: cost based on ACU capacity
                        serverless_cfg = cluster_serverless_config.get(cluster_id, {})
                        min_acu = serverless_cfg.get("min_capacity", 0)
                        max_acu = serverless_cfg.get("max_capacity", 0)
                        # Use min ACU for baseline cost estimate
                        hourly_cost = min_acu * SERVERLESS_V2_ACU_PRICE
                        # Store ACU info for display
                        instance_class = f"db.serverless ({min_acu}-{max_acu} ACU)"
                    else:
                        hourly_cost = get_rds_hourly_cost(instance_class, engine, multi_az) if status == "available" else 0.0

                    monthly_compute = hourly_cost * HOURS_PER_MONTH
                    monthly_storage = get_storage_monthly_cost(storage_type, storage_gb, iops) if not is_aurora else 0.0
                    monthly_total = monthly_compute + monthly_storage

                    results["instances"].append({
                        "AccountId": account_id,
                        "AccountName": account_name,
                        "Region": region,
                        "DBInstanceId": db_id,
                        "DBClusterId": cluster_id if cluster_id else "N/A",
                        "InstanceClass": instance_class,
                        "Engine": engine,
                        "EngineVersion": engine_version,
                        "Status": status,
                        "MultiAZ": "Yes" if multi_az else "No",
                        "StorageType": storage_type,
                        "StorageGB": storage_gb,
                        "IOPS": iops if iops else "N/A",
                        "VpcId": instance.get("DBSubnetGroup", {}).get("VpcId", "N/A"),
                        "Endpoint": instance.get("Endpoint", {}).get("Address", "N/A"),
                        "Port": instance.get("Endpoint", {}).get("Port", "N/A"),
                        "PubliclyAccessible": "Yes" if instance.get("PubliclyAccessible") else "No",
                        "Encrypted": "Yes" if instance.get("StorageEncrypted") else "No",
                        "BackupRetention": instance.get("BackupRetentionPeriod", 0),
                        "HourlyCost": f"${hourly_cost:.4f}" if hourly_cost > 0 else "N/A",
                        "MonthlyCost": f"${monthly_total:.2f}" if monthly_total > 0 else "N/A",
                        "CreatedTime": instance.get("InstanceCreateTime", "").strftime("%Y-%m-%d %H:%M:%S") if instance.get("InstanceCreateTime") else "N/A",
                    })

                # Process Aurora Clusters (exclude DocumentDB)
                for cluster in (clusters or []):
                    engine = cluster.get("Engine", "N/A")
                    # Skip DocumentDB clusters
                    if "docdb" in engine.lower():
                        continue
                    cluster_id = cluster.get("DBClusterIdentifier", "N/A")
                    engine_version = cluster.get("EngineVersion", "N/A")
                    status = cluster.get("Status", "N/A")
                    members = cluster.get("DBClusterMembers", [])
                    storage_gb = cluster.get("AllocatedStorage", 0)

                    # Aurora storage cost
                    monthly_storage = storage_gb * STORAGE_PRICING.get("aurora", 0.10) if status == "available" else 0.0

                    results["clusters"].append({
                        "AccountId": account_id,
                        "AccountName": account_name,
                        "Region": region,
                        "ClusterId": cluster_id,
                        "Engine": engine,
                        "EngineVersion": engine_version,
                        "Status": status,
                        "ClusterMembers": len(members),
                        "ReaderEndpoint": cluster.get("ReaderEndpoint", "N/A"),
                        "WriterEndpoint": cluster.get("Endpoint", "N/A"),
                        "Port": cluster.get("Port", "N/A"),
                        "MultiAZ": "Yes" if len(members) > 1 else "No",
                        "StorageGB": storage_gb,
                        "Encrypted": "Yes" if cluster.get("StorageEncrypted") else "No",
                        "DeletionProtection": "Yes" if cluster.get("DeletionProtection") else "No",
                        "BackupRetention": cluster.get("BackupRetentionPeriod", 0),
                        "MonthlyStorageCost": f"${monthly_storage:.2f}" if monthly_storage > 0 else "N/A",
                        "CreatedTime": cluster.get("ClusterCreateTime", "").strftime("%Y-%m-%d %H:%M:%S") if cluster.get("ClusterCreateTime") else "N/A",
                    })

                # Process DB Snapshots (exclude DocumentDB)
                for snapshot in (snapshots or []):
                    snap_engine = snapshot.get("Engine", "")
                    # Skip DocumentDB snapshots
                    if "docdb" in snap_engine.lower():
                        continue
                    snap_id = snapshot.get("DBSnapshotIdentifier", "N/A")
                    size_gb = snapshot.get("AllocatedStorage", 0)
                    # Snapshot storage: same as backup storage
                    monthly_cost = size_gb * 0.095  # Backup storage rate

                    results["snapshots"].append({
                        "AccountId": account_id,
                        "AccountName": account_name,
                        "Region": region,
                        "SnapshotId": snap_id,
                        "DBInstanceId": snapshot.get("DBInstanceIdentifier", "N/A"),
                        "Engine": snapshot.get("Engine", "N/A"),
                        "EngineVersion": snapshot.get("EngineVersion", "N/A"),
                        "SnapshotType": snapshot.get("SnapshotType", "N/A"),
                        "Status": snapshot.get("Status", "N/A"),
                        "StorageGB": size_gb,
                        "Encrypted": "Yes" if snapshot.get("Encrypted") else "No",
                        "MonthlyCost": f"${monthly_cost:.2f}",
                        "CreatedTime": snapshot.get("SnapshotCreateTime", "").strftime("%Y-%m-%d %H:%M:%S") if snapshot.get("SnapshotCreateTime") else "N/A",
                    })

                # Process Cluster Snapshots (exclude DocumentDB)
                for snapshot in (cluster_snapshots or []):
                    snap_engine = snapshot.get("Engine", "")
                    # Skip DocumentDB cluster snapshots
                    if "docdb" in snap_engine.lower():
                        continue
                    snap_id = snapshot.get("DBClusterSnapshotIdentifier", "N/A")
                    size_gb = snapshot.get("AllocatedStorage", 0)
                    monthly_cost = size_gb * 0.095

                    results["cluster_snapshots"].append({
                        "AccountId": account_id,
                        "AccountName": account_name,
                        "Region": region,
                        "SnapshotId": snap_id,
                        "ClusterId": snapshot.get("DBClusterIdentifier", "N/A"),
                        "Engine": snapshot.get("Engine", "N/A"),
                        "EngineVersion": snapshot.get("EngineVersion", "N/A"),
                        "SnapshotType": snapshot.get("SnapshotType", "N/A"),
                        "Status": snapshot.get("Status", "N/A"),
                        "StorageGB": size_gb,
                        "Encrypted": "Yes" if snapshot.get("StorageEncrypted") else "No",
                        "MonthlyCost": f"${monthly_cost:.2f}",
                        "CreatedTime": snapshot.get("SnapshotCreateTime", "").strftime("%Y-%m-%d %H:%M:%S") if snapshot.get("SnapshotCreateTime") else "N/A",
                    })

                # Process Reserved DB Instances
                for res in (reserved or []):
                    results["reserved"].append({
                        "AccountId": account_id,
                        "AccountName": account_name,
                        "Region": region,
                        "ReservedId": res.get("ReservedDBInstanceId", "N/A"),
                        "InstanceClass": res.get("DBInstanceClass", "N/A"),
                        "ProductDescription": res.get("ProductDescription", "N/A"),
                        "State": res.get("State", "N/A"),
                        "OfferingType": res.get("OfferingType", "N/A"),
                        "MultiAZ": "Yes" if res.get("MultiAZ") else "No",
                        "Duration": res.get("Duration", 0) // 31536000,  # Convert seconds to years
                        "InstanceCount": res.get("DBInstanceCount", 0),
                        "FixedPrice": f"${res.get('FixedPrice', 0):.2f}",
                        "RecurringCharges": f"${sum(r.get('RecurringChargeAmount', 0) for r in res.get('RecurringCharges', [])):.4f}/hr",
                        "StartTime": res.get("StartTime", "").strftime("%Y-%m-%d %H:%M:%S") if res.get("StartTime") else "N/A",
                    })

            except ClientError as e:
                if verbose:
                    print(f"    Error in {region}: {e}")
                continue
            except Exception as e:
                if verbose:
                    print(f"    Unexpected error in {region}: {e}")
                continue

        if account_scanned:
            scanned_accounts.add(account_id)
        else:
            failed_accounts.add(profile_name)

    results["scan_info"]["accounts_scanned"] = len(scanned_accounts)
    results["scan_info"]["accounts_failed"] = len(failed_accounts)

    return results


def export_to_json(results: dict, filename: str):
    """Export results to JSON file."""
    with open(filename, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"JSON exported to: {filename}")


def export_to_csv(results: dict, prefix: str):
    """Export results to CSV files."""
    # DB Instances CSV
    if results.get("instances"):
        instances_file = f"{prefix}_instances.csv"
        with open(instances_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results["instances"][0].keys())
            writer.writeheader()
            writer.writerows(results["instances"])
        print(f"Instances CSV saved to: {instances_file}")

    # Aurora Clusters CSV
    if results.get("clusters"):
        clusters_file = f"{prefix}_clusters.csv"
        with open(clusters_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results["clusters"][0].keys())
            writer.writeheader()
            writer.writerows(results["clusters"])
        print(f"Clusters CSV saved to: {clusters_file}")

    # DB Snapshots CSV
    if results.get("snapshots"):
        snapshots_file = f"{prefix}_snapshots.csv"
        with open(snapshots_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results["snapshots"][0].keys())
            writer.writeheader()
            writer.writerows(results["snapshots"])
        print(f"Snapshots CSV saved to: {snapshots_file}")

    # Cluster Snapshots CSV
    if results.get("cluster_snapshots"):
        cluster_snaps_file = f"{prefix}_cluster_snapshots.csv"
        with open(cluster_snaps_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results["cluster_snapshots"][0].keys())
            writer.writeheader()
            writer.writerows(results["cluster_snapshots"])
        print(f"Cluster Snapshots CSV saved to: {cluster_snaps_file}")

    # Reserved Instances CSV
    if results.get("reserved"):
        reserved_file = f"{prefix}_reserved.csv"
        with open(reserved_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results["reserved"][0].keys())
            writer.writeheader()
            writer.writerows(results["reserved"])
        print(f"Reserved Instances CSV saved to: {reserved_file}")


def export_to_html(results: dict, filename: str):
    """Export results to interactive HTML report."""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS RDS Scan Report</title>
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
        .status-available, .status-active { color: #1d8102; font-weight: bold; }
        .status-creating, .status-modifying, .status-backing-up { color: #ff9900; font-weight: bold; }
        .status-stopped, .status-deleted, .status-failed { color: #d13212; font-weight: bold; }
        .yes { color: #1d8102; }
        .no { color: #879596; }
        .timestamp { color: #879596; font-size: 12px; margin-bottom: 20px; }
        .result-count { color: #666; font-size: 13px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <h1>AWS RDS Scan Report</h1>
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
                <div class="label">DB Instances</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("clusters", []))) + """</div>
                <div class="label">Aurora Clusters</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("snapshots", [])) + len(results.get("cluster_snapshots", []))) + """</div>
                <div class="label">Snapshots</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("reserved", []))) + """</div>
                <div class="label">Reserved</div>
            </div>
        </div>
    </div>

    <div class="cost-summary">
        <strong>Estimated Monthly Costs</strong>
        <div class="cost-grid">
            <div class="cost-item">
                <div class="cost-value" id="instanceCost">$0.00</div>
                <div class="cost-label">DB Instances</div>
            </div>
            <div class="cost-item">
                <div class="cost-value" id="clusterCost">$0.00</div>
                <div class="cost-label">Aurora Storage</div>
            </div>
            <div class="cost-item">
                <div class="cost-value" id="snapshotCost">$0.00</div>
                <div class="cost-label">Snapshots</div>
            </div>
            <div class="cost-item cost-total">
                <div class="cost-value" id="totalCost">$0.00</div>
                <div class="cost-label">Total Monthly</div>
            </div>
        </div>
        <div class="cost-note">
            <strong>Note:</strong> Costs shown are on-demand pricing (us-east-1) based on AWS Price Calculator. Actual costs may be lower if using Reserved Instances, Savings Plans, or other discounts. Instance costs include compute only; storage costs are separate. Multi-AZ deployments are approximately 2x the shown price. Aurora Serverless v2 costs are estimated using minimum ACU capacity ($0.12/ACU-hour); actual costs depend on usage.
        </div>
    </div>

    <div class="tabs">
        <button class="tab active" onclick="showTab('instances')">DB Instances (""" + str(len(results.get("instances", []))) + """)</button>
        <button class="tab" onclick="showTab('clusters')">Aurora Clusters (""" + str(len(results.get("clusters", []))) + """)</button>
        <button class="tab" onclick="showTab('snapshots')">Manual Snapshots (""" + str(len(results.get("snapshots", []))) + """)</button>
        <button class="tab" onclick="showTab('clusterSnapshots')">Manual Cluster Snapshots (""" + str(len(results.get("cluster_snapshots", []))) + """)</button>
        <button class="tab" onclick="showTab('reserved')">Reserved (""" + str(len(results.get("reserved", []))) + """)</button>
    </div>
"""

    # DB Instances Tab
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
                <label>Engine</label>
                <select id="instancesEngine" onchange="filterTable('instances')">
                    <option value="">All Engines</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Status</label>
                <select id="instancesStatus" onchange="filterTable('instances')">
                    <option value="">All Status</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Multi-AZ</label>
                <select id="instancesMultiAZ" onchange="filterTable('instances')">
                    <option value="">All</option>
                    <option value="Yes">Yes</option>
                    <option value="No">No</option>
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
                    <th>DB Instance ID<span class="sort-icon"></span></th>
                    <th>Cluster ID<span class="sort-icon"></span></th>
                    <th>Instance Class<span class="sort-icon"></span></th>
                    <th>Engine<span class="sort-icon"></span></th>
                    <th>Version<span class="sort-icon"></span></th>
                    <th>Status<span class="sort-icon"></span></th>
                    <th>Multi-AZ<span class="sort-icon"></span></th>
                    <th>Storage Type<span class="sort-icon"></span></th>
                    <th>Storage GB<span class="sort-icon"></span></th>
                    <th>Encrypted<span class="sort-icon"></span></th>
                    <th>Public<span class="sort-icon"></span></th>
                    <th>Backup Days<span class="sort-icon"></span></th>
                    <th>Hourly Cost<span class="sort-icon"></span></th>
                    <th>Monthly Cost<span class="sort-icon"></span></th>
                    <th>Created<span class="sort-icon"></span></th>
                </tr>
            </thead>
            <tbody>
"""
    for instance in results.get("instances", []):
        status = instance["Status"]
        status_class = ""
        if status == "available":
            status_class = "status-available"
        elif status in ["creating", "modifying", "backing-up"]:
            status_class = "status-creating"
        elif status in ["stopped", "failed", "deleting"]:
            status_class = "status-stopped"
        multi_az_class = "yes" if instance["MultiAZ"] == "Yes" else "no"
        encrypted_class = "yes" if instance["Encrypted"] == "Yes" else "no"
        public_class = "no" if instance["PubliclyAccessible"] == "No" else "yes"
        html += f"""                <tr>
                    <td>{instance['AccountId']}</td>
                    <td>{instance['AccountName']}</td>
                    <td>{instance['Region']}</td>
                    <td>{instance['DBInstanceId']}</td>
                    <td>{instance['DBClusterId']}</td>
                    <td>{instance['InstanceClass']}</td>
                    <td>{instance['Engine']}</td>
                    <td>{instance['EngineVersion']}</td>
                    <td class="{status_class}">{instance['Status']}</td>
                    <td class="{multi_az_class}">{instance['MultiAZ']}</td>
                    <td>{instance['StorageType']}</td>
                    <td>{instance['StorageGB']}</td>
                    <td class="{encrypted_class}">{instance['Encrypted']}</td>
                    <td class="{public_class}">{instance['PubliclyAccessible']}</td>
                    <td>{instance['BackupRetention']}</td>
                    <td>{instance['HourlyCost']}</td>
                    <td>{instance['MonthlyCost']}</td>
                    <td>{instance['CreatedTime']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # Aurora Clusters Tab
    html += """
    <div id="clusters" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="clustersSearch" placeholder="Search..." onkeyup="filterTable('clusters')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="clustersAccount" onchange="filterTable('clusters')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="clustersRegion" onchange="filterTable('clusters')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Engine</label>
                <select id="clustersEngine" onchange="filterTable('clusters')">
                    <option value="">All Engines</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Status</label>
                <select id="clustersStatus" onchange="filterTable('clusters')">
                    <option value="">All Status</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('clusters')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="clustersCount">0</span> of """ + str(len(results.get("clusters", []))) + """ clusters</div>
        <div class="table-container">
        <table id="clustersTable">
            <thead>
                <tr>
                    <th>Account ID<span class="sort-icon"></span></th>
                    <th>Account Name<span class="sort-icon"></span></th>
                    <th>Region<span class="sort-icon"></span></th>
                    <th>Cluster ID<span class="sort-icon"></span></th>
                    <th>Engine<span class="sort-icon"></span></th>
                    <th>Version<span class="sort-icon"></span></th>
                    <th>Status<span class="sort-icon"></span></th>
                    <th>Members<span class="sort-icon"></span></th>
                    <th>Multi-AZ<span class="sort-icon"></span></th>
                    <th>Storage GB<span class="sort-icon"></span></th>
                    <th>Encrypted<span class="sort-icon"></span></th>
                    <th>Delete Protection<span class="sort-icon"></span></th>
                    <th>Backup Days<span class="sort-icon"></span></th>
                    <th>Storage Cost<span class="sort-icon"></span></th>
                    <th>Created<span class="sort-icon"></span></th>
                </tr>
            </thead>
            <tbody>
"""
    for cluster in results.get("clusters", []):
        status = cluster["Status"]
        status_class = ""
        if status == "available":
            status_class = "status-available"
        elif status in ["creating", "modifying", "backing-up"]:
            status_class = "status-creating"
        elif status in ["stopped", "failed", "deleting"]:
            status_class = "status-stopped"
        encrypted_class = "yes" if cluster["Encrypted"] == "Yes" else "no"
        del_prot_class = "yes" if cluster["DeletionProtection"] == "Yes" else "no"
        html += f"""                <tr>
                    <td>{cluster['AccountId']}</td>
                    <td>{cluster['AccountName']}</td>
                    <td>{cluster['Region']}</td>
                    <td>{cluster['ClusterId']}</td>
                    <td>{cluster['Engine']}</td>
                    <td>{cluster['EngineVersion']}</td>
                    <td class="{status_class}">{cluster['Status']}</td>
                    <td>{cluster['ClusterMembers']}</td>
                    <td>{cluster['MultiAZ']}</td>
                    <td>{cluster['StorageGB']}</td>
                    <td class="{encrypted_class}">{cluster['Encrypted']}</td>
                    <td class="{del_prot_class}">{cluster['DeletionProtection']}</td>
                    <td>{cluster['BackupRetention']}</td>
                    <td>{cluster['MonthlyStorageCost']}</td>
                    <td>{cluster['CreatedTime']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # DB Snapshots Tab
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
                <label>Engine</label>
                <select id="snapshotsEngine" onchange="filterTable('snapshots')">
                    <option value="">All Engines</option>
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
                    <th>DB Instance ID<span class="sort-icon"></span></th>
                    <th>Engine<span class="sort-icon"></span></th>
                    <th>Version<span class="sort-icon"></span></th>
                    <th>Type<span class="sort-icon"></span></th>
                    <th>Status<span class="sort-icon"></span></th>
                    <th>Storage GB<span class="sort-icon"></span></th>
                    <th>Encrypted<span class="sort-icon"></span></th>
                    <th>Monthly Cost<span class="sort-icon"></span></th>
                    <th>Created<span class="sort-icon"></span></th>
                </tr>
            </thead>
            <tbody>
"""
    for snap in results.get("snapshots", []):
        status = snap["Status"]
        status_class = "status-available" if status == "available" else ""
        encrypted_class = "yes" if snap["Encrypted"] == "Yes" else "no"
        html += f"""                <tr>
                    <td>{snap['AccountId']}</td>
                    <td>{snap['AccountName']}</td>
                    <td>{snap['Region']}</td>
                    <td>{snap['SnapshotId']}</td>
                    <td>{snap['DBInstanceId']}</td>
                    <td>{snap['Engine']}</td>
                    <td>{snap['EngineVersion']}</td>
                    <td>{snap['SnapshotType']}</td>
                    <td class="{status_class}">{snap['Status']}</td>
                    <td>{snap['StorageGB']}</td>
                    <td class="{encrypted_class}">{snap['Encrypted']}</td>
                    <td>{snap['MonthlyCost']}</td>
                    <td>{snap['CreatedTime']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # Cluster Snapshots Tab
    html += """
    <div id="clusterSnapshots" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="clusterSnapshotsSearch" placeholder="Search..." onkeyup="filterTable('clusterSnapshots')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="clusterSnapshotsAccount" onchange="filterTable('clusterSnapshots')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="clusterSnapshotsRegion" onchange="filterTable('clusterSnapshots')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('clusterSnapshots')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="clusterSnapshotsCount">0</span> of """ + str(len(results.get("cluster_snapshots", []))) + """ cluster snapshots</div>
        <div class="table-container">
        <table id="clusterSnapshotsTable">
            <thead>
                <tr>
                    <th>Account ID<span class="sort-icon"></span></th>
                    <th>Account Name<span class="sort-icon"></span></th>
                    <th>Region<span class="sort-icon"></span></th>
                    <th>Snapshot ID<span class="sort-icon"></span></th>
                    <th>Cluster ID<span class="sort-icon"></span></th>
                    <th>Engine<span class="sort-icon"></span></th>
                    <th>Version<span class="sort-icon"></span></th>
                    <th>Type<span class="sort-icon"></span></th>
                    <th>Status<span class="sort-icon"></span></th>
                    <th>Storage GB<span class="sort-icon"></span></th>
                    <th>Encrypted<span class="sort-icon"></span></th>
                    <th>Monthly Cost<span class="sort-icon"></span></th>
                    <th>Created<span class="sort-icon"></span></th>
                </tr>
            </thead>
            <tbody>
"""
    for snap in results.get("cluster_snapshots", []):
        status = snap["Status"]
        status_class = "status-available" if status == "available" else ""
        encrypted_class = "yes" if snap["Encrypted"] == "Yes" else "no"
        html += f"""                <tr>
                    <td>{snap['AccountId']}</td>
                    <td>{snap['AccountName']}</td>
                    <td>{snap['Region']}</td>
                    <td>{snap['SnapshotId']}</td>
                    <td>{snap['ClusterId']}</td>
                    <td>{snap['Engine']}</td>
                    <td>{snap['EngineVersion']}</td>
                    <td>{snap['SnapshotType']}</td>
                    <td class="{status_class}">{snap['Status']}</td>
                    <td>{snap['StorageGB']}</td>
                    <td class="{encrypted_class}">{snap['Encrypted']}</td>
                    <td>{snap['MonthlyCost']}</td>
                    <td>{snap['CreatedTime']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # Reserved Instances Tab
    html += """
    <div id="reserved" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="reservedSearch" placeholder="Search..." onkeyup="filterTable('reserved')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="reservedAccount" onchange="filterTable('reserved')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="reservedRegion" onchange="filterTable('reserved')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>State</label>
                <select id="reservedState" onchange="filterTable('reserved')">
                    <option value="">All States</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('reserved')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="reservedCount">0</span> of """ + str(len(results.get("reserved", []))) + """ reserved instances</div>
        <div class="table-container">
        <table id="reservedTable">
            <thead>
                <tr>
                    <th>Account ID<span class="sort-icon"></span></th>
                    <th>Account Name<span class="sort-icon"></span></th>
                    <th>Region<span class="sort-icon"></span></th>
                    <th>Reserved ID<span class="sort-icon"></span></th>
                    <th>Instance Class<span class="sort-icon"></span></th>
                    <th>Product<span class="sort-icon"></span></th>
                    <th>State<span class="sort-icon"></span></th>
                    <th>Offering Type<span class="sort-icon"></span></th>
                    <th>Multi-AZ<span class="sort-icon"></span></th>
                    <th>Duration (Yrs)<span class="sort-icon"></span></th>
                    <th>Count<span class="sort-icon"></span></th>
                    <th>Fixed Price<span class="sort-icon"></span></th>
                    <th>Recurring<span class="sort-icon"></span></th>
                    <th>Start Time<span class="sort-icon"></span></th>
                </tr>
            </thead>
            <tbody>
"""
    for res in results.get("reserved", []):
        state = res["State"]
        state_class = "status-active" if state == "active" else ""
        html += f"""                <tr>
                    <td>{res['AccountId']}</td>
                    <td>{res['AccountName']}</td>
                    <td>{res['Region']}</td>
                    <td>{res['ReservedId']}</td>
                    <td>{res['InstanceClass']}</td>
                    <td>{res['ProductDescription']}</td>
                    <td class="{state_class}">{res['State']}</td>
                    <td>{res['OfferingType']}</td>
                    <td>{res['MultiAZ']}</td>
                    <td>{res['Duration']}</td>
                    <td>{res['InstanceCount']}</td>
                    <td>{res['FixedPrice']}</td>
                    <td>{res['RecurringCharges']}</td>
                    <td>{res['StartTime']}</td>
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
function showTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    event.target.classList.add('active');
    updateCosts();
}

function filterTable(tabId) {
    const search = document.getElementById(tabId + 'Search').value.toLowerCase();
    const account = document.getElementById(tabId + 'Account').value;
    const region = document.getElementById(tabId + 'Region').value;

    let extraFilters = {};
    if (tabId === 'instances') {
        extraFilters.engine = document.getElementById('instancesEngine').value;
        extraFilters.status = document.getElementById('instancesStatus').value;
        extraFilters.multiAZ = document.getElementById('instancesMultiAZ').value;
    } else if (tabId === 'clusters') {
        extraFilters.engine = document.getElementById('clustersEngine').value;
        extraFilters.status = document.getElementById('clustersStatus').value;
    } else if (tabId === 'snapshots') {
        extraFilters.engine = document.getElementById('snapshotsEngine').value;
    } else if (tabId === 'reserved') {
        extraFilters.state = document.getElementById('reservedState').value;
    }

    const table = document.getElementById(tabId + 'Table');
    const rows = table.querySelectorAll('tbody tr');
    let visibleCount = 0;

    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        const text = Array.from(cells).map(c => c.textContent.toLowerCase()).join(' ');
        const rowAccount = cells[1].textContent;
        const rowRegion = cells[2].textContent;

        let show = text.includes(search);
        if (account && rowAccount !== account) show = false;
        if (region && rowRegion !== region) show = false;

        // Extra filters based on tab
        if (tabId === 'instances') {
            if (extraFilters.engine && cells[6].textContent !== extraFilters.engine) show = false;
            if (extraFilters.status && cells[8].textContent !== extraFilters.status) show = false;
            if (extraFilters.multiAZ && cells[9].textContent !== extraFilters.multiAZ) show = false;
        } else if (tabId === 'clusters') {
            if (extraFilters.engine && cells[4].textContent !== extraFilters.engine) show = false;
            if (extraFilters.status && cells[6].textContent !== extraFilters.status) show = false;
        } else if (tabId === 'snapshots') {
            if (extraFilters.engine && cells[5].textContent !== extraFilters.engine) show = false;
        } else if (tabId === 'reserved') {
            if (extraFilters.state && cells[6].textContent !== extraFilters.state) show = false;
        }

        row.classList.toggle('hidden', !show);
        if (show) visibleCount++;
    });

    document.getElementById(tabId + 'Count').textContent = visibleCount;
    updateCosts();
}

function clearFilters(tabId) {
    document.getElementById(tabId + 'Search').value = '';
    document.getElementById(tabId + 'Account').value = '';
    document.getElementById(tabId + 'Region').value = '';

    if (tabId === 'instances') {
        document.getElementById('instancesEngine').value = '';
        document.getElementById('instancesStatus').value = '';
        document.getElementById('instancesMultiAZ').value = '';
    } else if (tabId === 'clusters') {
        document.getElementById('clustersEngine').value = '';
        document.getElementById('clustersStatus').value = '';
    } else if (tabId === 'snapshots') {
        document.getElementById('snapshotsEngine').value = '';
    } else if (tabId === 'reserved') {
        document.getElementById('reservedState').value = '';
    }

    filterTable(tabId);
}

function populateFilters() {
    const tabs = ['instances', 'clusters', 'snapshots', 'clusterSnapshots', 'reserved'];

    tabs.forEach(tabId => {
        const table = document.getElementById(tabId + 'Table');
        if (!table) return;

        const rows = table.querySelectorAll('tbody tr');
        const accounts = new Set();
        const regions = new Set();
        const engines = new Set();
        const statuses = new Set();
        const states = new Set();

        rows.forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length > 2) {
                accounts.add(cells[1].textContent);
                regions.add(cells[2].textContent);
            }
            if (tabId === 'instances' && cells.length > 8) {
                engines.add(cells[6].textContent);
                statuses.add(cells[8].textContent);
            }
            if (tabId === 'clusters' && cells.length > 6) {
                engines.add(cells[4].textContent);
                statuses.add(cells[6].textContent);
            }
            if (tabId === 'snapshots' && cells.length > 5) {
                engines.add(cells[5].textContent);
            }
            if (tabId === 'reserved' && cells.length > 6) {
                states.add(cells[6].textContent);
            }
        });

        const accountSelect = document.getElementById(tabId + 'Account');
        const regionSelect = document.getElementById(tabId + 'Region');

        if (accountSelect) {
            [...accounts].sort().forEach(a => {
                const opt = document.createElement('option');
                opt.value = a;
                opt.textContent = a;
                accountSelect.appendChild(opt);
            });
        }

        if (regionSelect) {
            [...regions].sort().forEach(r => {
                const opt = document.createElement('option');
                opt.value = r;
                opt.textContent = r;
                regionSelect.appendChild(opt);
            });
        }

        if (tabId === 'instances') {
            const engineSelect = document.getElementById('instancesEngine');
            const statusSelect = document.getElementById('instancesStatus');
            [...engines].sort().forEach(e => {
                const opt = document.createElement('option');
                opt.value = e;
                opt.textContent = e;
                engineSelect.appendChild(opt);
            });
            [...statuses].sort().forEach(s => {
                const opt = document.createElement('option');
                opt.value = s;
                opt.textContent = s;
                statusSelect.appendChild(opt);
            });
        }

        if (tabId === 'clusters') {
            const engineSelect = document.getElementById('clustersEngine');
            const statusSelect = document.getElementById('clustersStatus');
            if (engineSelect) {
                [...engines].sort().forEach(e => {
                    const opt = document.createElement('option');
                    opt.value = e;
                    opt.textContent = e;
                    engineSelect.appendChild(opt);
                });
            }
            if (statusSelect) {
                [...statuses].sort().forEach(s => {
                    const opt = document.createElement('option');
                    opt.value = s;
                    opt.textContent = s;
                    statusSelect.appendChild(opt);
                });
            }
        }

        if (tabId === 'snapshots') {
            const engineSelect = document.getElementById('snapshotsEngine');
            if (engineSelect) {
                [...engines].sort().forEach(e => {
                    const opt = document.createElement('option');
                    opt.value = e;
                    opt.textContent = e;
                    engineSelect.appendChild(opt);
                });
            }
        }

        if (tabId === 'reserved') {
            const stateSelect = document.getElementById('reservedState');
            if (stateSelect) {
                [...states].sort().forEach(s => {
                    const opt = document.createElement('option');
                    opt.value = s;
                    opt.textContent = s;
                    stateSelect.appendChild(opt);
                });
            }
        }
    });
}

function sortTable(tableId, colIndex) {
    const table = document.getElementById(tableId);
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const th = table.querySelectorAll('th')[colIndex];

    const isAsc = th.classList.contains('sort-asc');
    table.querySelectorAll('th').forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
    th.classList.add(isAsc ? 'sort-desc' : 'sort-asc');

    rows.sort((a, b) => {
        let aVal = a.cells[colIndex].textContent.trim();
        let bVal = b.cells[colIndex].textContent.trim();

        // Try numeric sort
        const aNum = parseFloat(aVal.replace(/[$,]/g, ''));
        const bNum = parseFloat(bVal.replace(/[$,]/g, ''));
        if (!isNaN(aNum) && !isNaN(bNum)) {
            return isAsc ? bNum - aNum : aNum - bNum;
        }

        return isAsc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
    });

    rows.forEach(row => tbody.appendChild(row));
}

function updateCosts() {
    let instanceTotal = 0;
    let clusterTotal = 0;
    let snapshotTotal = 0;

    // Calculate DB Instance costs (MonthlyCost is column 16)
    const instancesTable = document.getElementById('instancesTable');
    if (instancesTable) {
        const rows = instancesTable.querySelectorAll('tbody tr');
        rows.forEach(row => {
            if (!row.classList.contains('hidden')) {
                const costCell = row.cells[16];
                if (costCell) {
                    const cost = parseFloat(costCell.textContent.replace('$', '').replace(',', '').replace('N/A', '0')) || 0;
                    instanceTotal += cost;
                }
            }
        });
    }

    // Calculate Aurora Cluster storage costs (MonthlyStorageCost is column 13)
    const clustersTable = document.getElementById('clustersTable');
    if (clustersTable) {
        const rows = clustersTable.querySelectorAll('tbody tr');
        rows.forEach(row => {
            if (!row.classList.contains('hidden')) {
                const costCell = row.cells[13];
                if (costCell) {
                    const cost = parseFloat(costCell.textContent.replace('$', '').replace(',', '').replace('N/A', '0')) || 0;
                    clusterTotal += cost;
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
                    const cost = parseFloat(costCell.textContent.replace('$', '').replace(',', '').replace('N/A', '0')) || 0;
                    snapshotTotal += cost;
                }
            }
        });
    }

    // Add cluster snapshot costs (MonthlyCost is column 11)
    const clusterSnapshotsTable = document.getElementById('clusterSnapshotsTable');
    if (clusterSnapshotsTable) {
        const rows = clusterSnapshotsTable.querySelectorAll('tbody tr');
        rows.forEach(row => {
            if (!row.classList.contains('hidden')) {
                const costCell = row.cells[11];
                if (costCell) {
                    const cost = parseFloat(costCell.textContent.replace('$', '').replace(',', '').replace('N/A', '0')) || 0;
                    snapshotTotal += cost;
                }
            }
        });
    }

    const total = instanceTotal + clusterTotal + snapshotTotal;

    document.getElementById('instanceCost').textContent = '$' + instanceTotal.toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2});
    document.getElementById('clusterCost').textContent = '$' + clusterTotal.toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2});
    document.getElementById('snapshotCost').textContent = '$' + snapshotTotal.toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2});
    document.getElementById('totalCost').textContent = '$' + total.toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2});
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

// Initialize
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
    ['instances', 'clusters', 'snapshots', 'clusterSnapshots', 'reserved'].forEach(tab => {
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
    print(f"  DB Instances: {len(results.get('instances', [])):,}")
    print(f"  Aurora Clusters: {len(results.get('clusters', [])):,}")
    print(f"  DB Snapshots: {len(results.get('snapshots', [])):,}")
    print(f"  Cluster Snapshots: {len(results.get('cluster_snapshots', [])):,}")
    print(f"  Reserved Instances: {len(results.get('reserved', [])):,}")

    # Calculate total costs
    instance_cost = sum(float(i['MonthlyCost'].replace('$', '').replace(',', '').replace('N/A', '0')) for i in results.get('instances', []))
    cluster_cost = sum(float(c['MonthlyStorageCost'].replace('$', '').replace(',', '').replace('N/A', '0')) for c in results.get('clusters', []))
    snapshot_cost = sum(float(s['MonthlyCost'].replace('$', '').replace(',', '')) for s in results.get('snapshots', []))
    cluster_snap_cost = sum(float(s['MonthlyCost'].replace('$', '').replace(',', '')) for s in results.get('cluster_snapshots', []))
    total_cost = instance_cost + cluster_cost + snapshot_cost + cluster_snap_cost

    print()
    print("Estimated Monthly Costs:")
    print(f"  DB Instances: ${instance_cost:,.2f}")
    print(f"  Aurora Storage: ${cluster_cost:,.2f}")
    print(f"  Snapshots: ${snapshot_cost + cluster_snap_cost:,.2f}")
    print(f"  Total: ${total_cost:,.2f}")
    print("  (Note: Costs are on-demand pricing, us-east-1. Actual costs may be lower with Reserved Instances.)")


def main():
    parser = argparse.ArgumentParser(
        description="Scan RDS resources across multiple AWS accounts"
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
        profiles = {args.profile: args.profile.replace(args.profile_pattern, "").strip("-._")}
    else:
        profiles = get_aws_profiles(args.profile_pattern)

    if not profiles:
        print(f"No profiles found matching pattern: {args.profile_pattern}")
        sys.exit(1)

    regions = [r.strip() for r in args.regions.split(",")]

    print(f"Found {len(profiles)} profile(s) to scan")
    print(f"Regions: {', '.join(regions)}")
    print("=" * 60)

    # Scan accounts
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
