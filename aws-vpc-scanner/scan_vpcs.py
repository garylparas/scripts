#!/usr/bin/env python3
"""
AWS VPC Scanner

Scans VPC resources across multiple AWS accounts and regions,
iterating through AWS profiles.
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


DEFAULT_REGIONS = ["us-east-1", "us-west-2"]

# AWS Pricing (USD) - as of 2024
# https://aws.amazon.com/vpc/pricing/
# https://aws.amazon.com/transit-gateway/pricing/
PRICING = {
    "nat_gateway_hourly": 0.045,      # Per hour when available
    "vpc_endpoint_interface_hourly": 0.01,  # Per hour per AZ (Gateway endpoints are free)
    "elastic_ip_hourly": 0.005,       # Per hour for all public IPv4 (as of Feb 2024)
    "transit_gateway_attachment_hourly": 0.05,  # Per attachment per hour
}
HOURS_PER_MONTH = 730  # Average hours in a month


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


def get_vpcs(ec2_client) -> list:
    """Get all VPCs."""
    vpcs = []
    paginator = ec2_client.get_paginator("describe_vpcs")
    for page in paginator.paginate():
        vpcs.extend(page.get("Vpcs", []))
    return vpcs


def get_subnets(ec2_client) -> list:
    """Get all subnets."""
    subnets = []
    paginator = ec2_client.get_paginator("describe_subnets")
    for page in paginator.paginate():
        subnets.extend(page.get("Subnets", []))
    return subnets


def get_internet_gateways(ec2_client) -> list:
    """Get all internet gateways."""
    igws = []
    paginator = ec2_client.get_paginator("describe_internet_gateways")
    for page in paginator.paginate():
        igws.extend(page.get("InternetGateways", []))
    return igws


def get_nat_gateways(ec2_client) -> list:
    """Get all NAT gateways."""
    nats = []
    paginator = ec2_client.get_paginator("describe_nat_gateways")
    for page in paginator.paginate():
        nats.extend(page.get("NatGateways", []))
    return nats


def get_route_tables(ec2_client) -> list:
    """Get all route tables."""
    rts = []
    paginator = ec2_client.get_paginator("describe_route_tables")
    for page in paginator.paginate():
        rts.extend(page.get("RouteTables", []))
    return rts


def get_security_groups(ec2_client) -> list:
    """Get all security groups."""
    sgs = []
    paginator = ec2_client.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        sgs.extend(page.get("SecurityGroups", []))
    return sgs


def get_network_interfaces(ec2_client) -> list:
    """Get all network interfaces."""
    enis = []
    paginator = ec2_client.get_paginator("describe_network_interfaces")
    for page in paginator.paginate():
        enis.extend(page.get("NetworkInterfaces", []))
    return enis


def get_vpc_endpoints(ec2_client) -> list:
    """Get all VPC endpoints."""
    endpoints = []
    paginator = ec2_client.get_paginator("describe_vpc_endpoints")
    for page in paginator.paginate():
        endpoints.extend(page.get("VpcEndpoints", []))
    return endpoints


def get_vpc_peering_connections(ec2_client) -> list:
    """Get all VPC peering connections."""
    peerings = []
    paginator = ec2_client.get_paginator("describe_vpc_peering_connections")
    for page in paginator.paginate():
        peerings.extend(page.get("VpcPeeringConnections", []))
    return peerings


def get_flow_logs(ec2_client) -> dict:
    """Get all flow logs and return a dict mapping VPC ID to flow log status."""
    flow_logs = {}
    paginator = ec2_client.get_paginator("describe_flow_logs")
    for page in paginator.paginate():
        for fl in page.get("FlowLogs", []):
            resource_id = fl.get("ResourceId", "")
            if resource_id.startswith("vpc-"):
                flow_logs[resource_id] = True
    return flow_logs


def get_flow_logs_detailed(ec2_client) -> list:
    """Get all flow logs with full details."""
    flow_logs = []
    paginator = ec2_client.get_paginator("describe_flow_logs")
    for page in paginator.paginate():
        flow_logs.extend(page.get("FlowLogs", []))
    return flow_logs


def get_elastic_ips(ec2_client) -> list:
    """Get all Elastic IPs."""
    response = ec2_client.describe_addresses()
    return response.get("Addresses", [])


def get_transit_gateway_attachments(ec2_client) -> list:
    """Get all Transit Gateway attachments."""
    attachments = []
    paginator = ec2_client.get_paginator("describe_transit_gateway_attachments")
    for page in paginator.paginate():
        attachments.extend(page.get("TransitGatewayAttachments", []))
    return attachments


def is_subnet_public(subnet_id: str, route_tables: list) -> bool:
    """Check if a subnet is public (has route to IGW)."""
    for rt in route_tables:
        # Check if this route table is associated with the subnet
        for assoc in rt.get("Associations", []):
            if assoc.get("SubnetId") == subnet_id:
                # Check routes for IGW
                for route in rt.get("Routes", []):
                    if route.get("GatewayId", "").startswith("igw-"):
                        return True
    return False


def scan_region(session: boto3.Session, region: str, account_id: str, account_name: str, verbose: bool = False) -> dict:
    """Scan a single region for VPC resources."""
    results = {
        "vpcs": [],
        "subnets": [],
        "internet_gateways": [],
        "nat_gateways": [],
        "route_tables": [],
        "security_groups": [],
        "vpc_endpoints": [],
        "vpc_peering": [],
        "flow_logs": [],
        "elastic_ips": [],
        "transit_gateway_attachments": [],
    }

    try:
        ec2 = session.client("ec2", region_name=region)

        # Get all resources
        vpcs = get_vpcs(ec2)
        subnets = get_subnets(ec2)
        igws = get_internet_gateways(ec2)
        nats = get_nat_gateways(ec2)
        rts = get_route_tables(ec2)
        sgs = get_security_groups(ec2)
        enis = get_network_interfaces(ec2)
        endpoints = get_vpc_endpoints(ec2)
        peerings = get_vpc_peering_connections(ec2)
        flow_logs = get_flow_logs(ec2)
        flow_logs_detailed = get_flow_logs_detailed(ec2)
        eips = get_elastic_ips(ec2)
        tgw_attachments = get_transit_gateway_attachments(ec2)

        if verbose:
            print(f"    VPCs: {len(vpcs)}, Subnets: {len(subnets)}, IGWs: {len(igws)}, NATs: {len(nats)}, TGW Attachments: {len(tgw_attachments)}")

        # Process VPCs
        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            has_flow_logs = "Yes" if vpc_id in flow_logs else "No"
            results["vpcs"].append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Region": region,
                "VpcId": vpc_id,
                "VpcName": get_resource_name(vpc.get("Tags")),
                "CidrBlock": vpc["CidrBlock"],
                "State": vpc["State"],
                "FlowLogsEnabled": has_flow_logs,
                "DhcpOptionsId": vpc.get("DhcpOptionsId", "N/A"),
            })

        # Process Subnets
        for subnet in subnets:
            is_public = is_subnet_public(subnet["SubnetId"], rts)
            results["subnets"].append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Region": region,
                "SubnetId": subnet["SubnetId"],
                "SubnetName": get_resource_name(subnet.get("Tags")),
                "VpcId": subnet["VpcId"],
                "CidrBlock": subnet["CidrBlock"],
                "AvailabilityZone": subnet["AvailabilityZone"],
                "AvailableIps": subnet["AvailableIpAddressCount"],
                "IsPublic": "Yes" if is_public else "No",
                "MapPublicIp": "Yes" if subnet.get("MapPublicIpOnLaunch", False) else "No",
                "State": subnet["State"],
            })

        # Process Internet Gateways
        for igw in igws:
            attached_vpc = "N/A"
            state = "detached"
            for attachment in igw.get("Attachments", []):
                attached_vpc = attachment.get("VpcId", "N/A")
                state = attachment.get("State", "detached")
            results["internet_gateways"].append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Region": region,
                "InternetGatewayId": igw["InternetGatewayId"],
                "IgwName": get_resource_name(igw.get("Tags")),
                "VpcId": attached_vpc,
                "State": state,
            })

        # Build subnet to AZ lookup
        subnet_az_map = {s["SubnetId"]: s["AvailabilityZone"] for s in subnets}

        # Process NAT Gateways
        for nat in nats:
            public_ip = "N/A"
            for addr in nat.get("NatGatewayAddresses", []):
                if addr.get("PublicIp"):
                    public_ip = addr["PublicIp"]
                    break
            nat_subnet_id = nat.get("SubnetId", "N/A")
            nat_az = subnet_az_map.get(nat_subnet_id, "N/A")
            # NAT Gateways are zonal (deployed in specific AZ)
            availability = f"Zonal ({nat_az})" if nat_az != "N/A" else "N/A"
            # Calculate costs (only for available NAT Gateways)
            nat_state = nat["State"]
            if nat_state == "available":
                hourly_cost = PRICING["nat_gateway_hourly"]
                monthly_cost = hourly_cost * HOURS_PER_MONTH
            else:
                hourly_cost = 0.0
                monthly_cost = 0.0
            results["nat_gateways"].append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Region": region,
                "NatGatewayId": nat["NatGatewayId"],
                "NatName": get_resource_name(nat.get("Tags")),
                "VpcId": nat.get("VpcId", "N/A"),
                "SubnetId": nat_subnet_id,
                "Availability": availability,
                "State": nat_state,
                "ConnectivityType": nat.get("ConnectivityType", "public"),
                "PublicIp": public_ip,
                "HourlyCost": f"${hourly_cost:.4f}",
                "MonthlyCost": f"${monthly_cost:.2f}",
                "CreateTime": nat.get("CreateTime", "").strftime("%Y-%m-%d %H:%M:%S") if nat.get("CreateTime") else "N/A",
            })

        # Process Route Tables
        for rt in rts:
            is_main = any(assoc.get("Main", False) for assoc in rt.get("Associations", []))
            associated_subnets = [assoc.get("SubnetId") for assoc in rt.get("Associations", []) if assoc.get("SubnetId")]
            results["route_tables"].append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Region": region,
                "RouteTableId": rt["RouteTableId"],
                "RtName": get_resource_name(rt.get("Tags")),
                "VpcId": rt["VpcId"],
                "IsMain": "Yes" if is_main else "No",
                "RoutesCount": len(rt.get("Routes", [])),
                "AssociatedSubnets": len(associated_subnets),
                "SubnetIds": ",".join(associated_subnets) if associated_subnets else "N/A",
            })

        # Build dict of SG ID -> count of ENIs using it
        sg_eni_count = {}
        for eni in enis:
            for group in eni.get("Groups", []):
                sg_id = group.get("GroupId")
                sg_eni_count[sg_id] = sg_eni_count.get(sg_id, 0) + 1

        # Build dict of SG ID -> list of SG IDs that reference it in their rules
        sg_referenced_by = {}
        for sg in sgs:
            referencing_sg_id = sg["GroupId"]
            # Check inbound rules
            for rule in sg.get("IpPermissions", []):
                for pair in rule.get("UserIdGroupPairs", []):
                    referenced_sg_id = pair.get("GroupId")
                    if referenced_sg_id:
                        if referenced_sg_id not in sg_referenced_by:
                            sg_referenced_by[referenced_sg_id] = set()
                        sg_referenced_by[referenced_sg_id].add(referencing_sg_id)
            # Check outbound rules
            for rule in sg.get("IpPermissionsEgress", []):
                for pair in rule.get("UserIdGroupPairs", []):
                    referenced_sg_id = pair.get("GroupId")
                    if referenced_sg_id:
                        if referenced_sg_id not in sg_referenced_by:
                            sg_referenced_by[referenced_sg_id] = set()
                        sg_referenced_by[referenced_sg_id].add(referencing_sg_id)

        # Process Security Groups
        for sg in sgs:
            sg_id = sg["GroupId"]
            eni_count = sg_eni_count.get(sg_id, 0)
            referencing_sgs = sg_referenced_by.get(sg_id, set())

            # Build UsedBy details
            used_by_parts = []
            if eni_count > 0:
                used_by_parts.append(f"{eni_count} ENI" + ("s" if eni_count > 1 else ""))
            if referencing_sgs:
                used_by_parts.append(", ".join(sorted(referencing_sgs)))

            used_by = "; ".join(used_by_parts) if used_by_parts else "None"
            in_use = "Yes" if (eni_count > 0 or referencing_sgs) else "No"

            results["security_groups"].append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Region": region,
                "SecurityGroupId": sg_id,
                "GroupName": sg["GroupName"],
                "VpcId": sg.get("VpcId", "N/A"),
                "Description": sg.get("Description", "N/A"),
                "InboundRulesCount": len(sg.get("IpPermissions", [])),
                "OutboundRulesCount": len(sg.get("IpPermissionsEgress", [])),
                "InUse": in_use,
                "UsedBy": used_by,
            })

        # Process VPC Endpoints
        for endpoint in endpoints:
            endpoint_type = endpoint["VpcEndpointType"]
            endpoint_state = endpoint["State"]
            # Calculate costs (Interface endpoints cost money, Gateway endpoints are free)
            # Only charge when endpoint is available
            if endpoint_type == "Interface" and endpoint_state == "available":
                hourly_cost = PRICING["vpc_endpoint_interface_hourly"]
                monthly_cost = hourly_cost * HOURS_PER_MONTH
            else:
                hourly_cost = 0.0
                monthly_cost = 0.0
            results["vpc_endpoints"].append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Region": region,
                "VpcEndpointId": endpoint["VpcEndpointId"],
                "EndpointName": get_resource_name(endpoint.get("Tags")),
                "VpcId": endpoint["VpcId"],
                "ServiceName": endpoint["ServiceName"],
                "EndpointType": endpoint_type,
                "State": endpoint_state,
                "HourlyCost": f"${hourly_cost:.4f}",
                "MonthlyCost": f"${monthly_cost:.2f}",
                "CreationTime": endpoint.get("CreationTimestamp", "").strftime("%Y-%m-%d %H:%M:%S") if endpoint.get("CreationTimestamp") else "N/A",
            })

        # Process VPC Peering Connections
        for peering in peerings:
            requester = peering.get("RequesterVpcInfo", {})
            accepter = peering.get("AccepterVpcInfo", {})
            status = peering.get("Status", {})
            results["vpc_peering"].append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Region": region,
                "PeeringConnectionId": peering["VpcPeeringConnectionId"],
                "PeeringName": get_resource_name(peering.get("Tags")),
                "RequesterVpcId": requester.get("VpcId", "N/A"),
                "RequesterCidr": requester.get("CidrBlock", "N/A"),
                "RequesterAccountId": requester.get("OwnerId", "N/A"),
                "AccepterVpcId": accepter.get("VpcId", "N/A"),
                "AccepterCidr": accepter.get("CidrBlock", "N/A"),
                "AccepterAccountId": accepter.get("OwnerId", "N/A"),
                "Status": status.get("Code", "N/A"),
            })

        # Process Flow Logs
        for fl in flow_logs_detailed:
            # Determine destination
            log_dest_type = fl.get("LogDestinationType", "N/A")
            if log_dest_type == "cloud-watch-logs":
                destination = fl.get("LogGroupName", "N/A")
            elif log_dest_type == "s3":
                destination = fl.get("LogDestination", "N/A")
            else:
                destination = fl.get("LogDestination", "N/A")

            results["flow_logs"].append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Region": region,
                "FlowLogId": fl["FlowLogId"],
                "FlowLogName": get_resource_name(fl.get("Tags")),
                "ResourceId": fl.get("ResourceId", "N/A"),
                "ResourceType": fl.get("ResourceType", "N/A"),
                "TrafficType": fl.get("TrafficType", "N/A"),
                "Status": fl.get("FlowLogStatus", "N/A"),
                "DestinationType": log_dest_type,
                "Destination": destination,
                "CreationTime": fl.get("CreationTime", "").strftime("%Y-%m-%d %H:%M:%S") if fl.get("CreationTime") else "N/A",
            })

        # Build lookup from Public IP to NAT Gateway ID
        eip_to_nat = {}
        for nat in nats:
            nat_id = nat["NatGatewayId"]
            for addr in nat.get("NatGatewayAddresses", []):
                public_ip = addr.get("PublicIp")
                if public_ip:
                    eip_to_nat[public_ip] = nat_id

        # Process Elastic IPs
        for eip in eips:
            # Determine association status
            instance_id = eip.get("InstanceId", "")
            eni_id = eip.get("NetworkInterfaceId", "")
            association_id = eip.get("AssociationId", "")
            public_ip = eip.get("PublicIp", "")

            if instance_id:
                associated_with = f"Instance: {instance_id}"
                status = "Associated"
            elif eni_id:
                associated_with = f"ENI: {eni_id}"
                status = "Associated"
            else:
                associated_with = "None"
                status = "Available"

            # Check if EIP is associated with a NAT Gateway
            nat_gateway_id = eip_to_nat.get(public_ip, "N/A")

            # Calculate costs (all public IPv4 addresses cost $0.005/hr as of Feb 2024)
            hourly_cost = PRICING["elastic_ip_hourly"]
            monthly_cost = hourly_cost * HOURS_PER_MONTH

            results["elastic_ips"].append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Region": region,
                "AllocationId": eip.get("AllocationId", "N/A"),
                "PublicIp": public_ip if public_ip else "N/A",
                "EipName": get_resource_name(eip.get("Tags")),
                "PrivateIp": eip.get("PrivateIpAddress", "N/A"),
                "AssociatedWith": associated_with,
                "NatGatewayId": nat_gateway_id,
                "Status": status,
                "HourlyCost": f"${hourly_cost:.4f}",
                "MonthlyCost": f"${monthly_cost:.2f}",
                "Domain": eip.get("Domain", "N/A"),
                "NetworkBorderGroup": eip.get("NetworkBorderGroup", "N/A"),
            })

        # Process Transit Gateway Attachments
        for tgw_att in tgw_attachments:
            tgw_att_state = tgw_att.get("State", "N/A")
            # Calculate costs (only for available attachments)
            if tgw_att_state == "available":
                hourly_cost = PRICING["transit_gateway_attachment_hourly"]
                monthly_cost = hourly_cost * HOURS_PER_MONTH
            else:
                hourly_cost = 0.0
                monthly_cost = 0.0
            results["transit_gateway_attachments"].append({
                "AccountId": account_id,
                "AccountName": account_name,
                "Region": region,
                "TransitGatewayAttachmentId": tgw_att.get("TransitGatewayAttachmentId", "N/A"),
                "TransitGatewayId": tgw_att.get("TransitGatewayId", "N/A"),
                "TransitGatewayOwnerId": tgw_att.get("TransitGatewayOwnerId", "N/A"),
                "ResourceOwnerId": tgw_att.get("ResourceOwnerId", "N/A"),
                "ResourceType": tgw_att.get("ResourceType", "N/A"),
                "ResourceId": tgw_att.get("ResourceId", "N/A"),
                "State": tgw_att_state,
                "AttachmentName": get_resource_name(tgw_att.get("Tags")),
                "HourlyCost": f"${hourly_cost:.4f}",
                "MonthlyCost": f"${monthly_cost:.2f}",
                "CreationTime": tgw_att.get("CreationTime", "").strftime("%Y-%m-%d %H:%M:%S") if tgw_att.get("CreationTime") else "N/A",
            })

        return results

    except ClientError as e:
        if verbose:
            print(f"    Error scanning region {region}: {e}")
        return results


def scan_account(profile_name: str, account_name: str, regions: list, verbose: bool = False) -> dict:
    """Scan a single AWS account for VPC resources across regions."""
    all_results = {
        "vpcs": [],
        "subnets": [],
        "internet_gateways": [],
        "nat_gateways": [],
        "flow_logs": [],
        "elastic_ips": [],
        "transit_gateway_attachments": [],
        "route_tables": [],
        "security_groups": [],
        "vpc_endpoints": [],
        "vpc_peering": [],
    }

    try:
        session = boto3.Session(profile_name=profile_name)
        account_id = get_account_id(session)

        if not account_id:
            print(f"  Skipping {profile_name}: Unable to get account ID (credentials may be expired)")
            return all_results

        for region in regions:
            if verbose:
                print(f"  Scanning region: {region}")

            region_results = scan_region(session, region, account_id, account_name, verbose)

            # Merge results
            for key in all_results:
                all_results[key].extend(region_results.get(key, []))

        return all_results

    except ProfileNotFound:
        print(f"  Skipping {profile_name}: Profile not found")
        return all_results
    except (NoCredentialsError, TokenRetrievalError, SSOTokenLoadError):
        print(f"  Skipping {profile_name}: Credentials expired or unavailable (run 'aws sso login')")
        return all_results
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "AccessDenied":
            print(f"  Skipping {profile_name}: Access denied to EC2")
        else:
            print(f"  Skipping {profile_name}: {e}")
        return all_results
    except Exception as e:
        # Catch any other credential-related errors
        if "token" in str(e).lower() or "credential" in str(e).lower() or "sso" in str(e).lower():
            print(f"  Skipping {profile_name}: SSO/Credential error (run 'aws sso login')")
            return all_results
        print(f"  Skipping {profile_name}: Unexpected error - {e}")
        return all_results


def print_report(results: dict, verbose: bool = False):
    """Print results to console in a formatted way."""
    vpcs = results.get("vpcs", [])
    subnets = results.get("subnets", [])
    igws = results.get("internet_gateways", [])
    nats = results.get("nat_gateways", [])
    sgs = results.get("security_groups", [])

    if not vpcs:
        print("\nNo VPCs found.")
        return

    # Group by account
    accounts = {}
    for vpc in vpcs:
        key = (vpc["AccountId"], vpc["AccountName"])
        if key not in accounts:
            accounts[key] = {"vpcs": [], "regions": set()}
        accounts[key]["vpcs"].append(vpc)
        accounts[key]["regions"].add(vpc["Region"])

    print(f"\n{'='*80}")
    print("VPC SCAN RESULTS")
    print(f"{'='*80}")

    for (account_id, account_name), data in sorted(accounts.items()):
        account_vpcs = data["vpcs"]
        account_subnets = [s for s in subnets if s["AccountId"] == account_id]
        account_igws = [i for i in igws if i["AccountId"] == account_id]
        account_nats = [n for n in nats if n["AccountId"] == account_id]
        account_sgs = [s for s in sgs if s["AccountId"] == account_id]

        print(f"\nAccount: {account_name} ({account_id})")
        print(f"  Regions: {', '.join(sorted(data['regions']))}")
        print(f"  VPCs: {len(account_vpcs)}")
        print(f"  Subnets: {len(account_subnets)}")
        print(f"  Internet Gateways: {len(account_igws)}")
        print(f"  NAT Gateways: {len(account_nats)}")
        print(f"  Security Groups: {len(account_sgs)}")

        if verbose:
            for vpc in account_vpcs:
                flow_logs_marker = " [Flow Logs: Enabled]" if vpc["FlowLogsEnabled"] == "Yes" else " [Flow Logs: Disabled]"
                print(f"\n    VPC: {vpc['VpcId']} - {vpc['VpcName']}{flow_logs_marker}")
                print(f"      CIDR: {vpc['CidrBlock']} | Region: {vpc['Region']} | State: {vpc['State']}")

                # Show subnets for this VPC
                vpc_subnets = [s for s in account_subnets if s["VpcId"] == vpc["VpcId"]]
                if vpc_subnets:
                    print(f"      Subnets ({len(vpc_subnets)}):")
                    for subnet in vpc_subnets:
                        pub_marker = "Public" if subnet["IsPublic"] == "Yes" else "Private"
                        print(f"        - {subnet['SubnetId']} ({subnet['SubnetName']}) {subnet['CidrBlock']} [{pub_marker}] {subnet['AvailabilityZone']}")


def write_csv(results: dict, filepath: str):
    """Write results to multiple CSV files."""
    if not any(results.values()):
        print("No results to write to CSV.")
        return

    base_path = filepath.rsplit(".", 1)[0] if "." in filepath else filepath

    # Write VPCs
    if results.get("vpcs"):
        vpc_file = f"{base_path}_vpcs.csv"
        fieldnames = ["AccountId", "AccountName", "Region", "VpcId", "VpcName", "CidrBlock", "State", "FlowLogsEnabled", "DhcpOptionsId"]
        with open(vpc_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results["vpcs"])
        print(f"VPCs CSV saved to: {vpc_file}")

    # Write Subnets
    if results.get("subnets"):
        subnet_file = f"{base_path}_subnets.csv"
        fieldnames = ["AccountId", "AccountName", "Region", "SubnetId", "SubnetName", "VpcId", "CidrBlock", "AvailabilityZone", "AvailableIps", "IsPublic", "MapPublicIp", "State"]
        with open(subnet_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results["subnets"])
        print(f"Subnets CSV saved to: {subnet_file}")

    # Write Internet Gateways
    if results.get("internet_gateways"):
        igw_file = f"{base_path}_igws.csv"
        fieldnames = ["AccountId", "AccountName", "Region", "InternetGatewayId", "IgwName", "VpcId", "State"]
        with open(igw_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results["internet_gateways"])
        print(f"Internet Gateways CSV saved to: {igw_file}")

    # Write NAT Gateways
    if results.get("nat_gateways"):
        nat_file = f"{base_path}_nats.csv"
        fieldnames = ["AccountId", "AccountName", "Region", "NatGatewayId", "NatName", "VpcId", "SubnetId", "Availability", "State", "ConnectivityType", "PublicIp", "HourlyCost", "MonthlyCost", "CreateTime"]
        with open(nat_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results["nat_gateways"])
        print(f"NAT Gateways CSV saved to: {nat_file}")

    # Write Route Tables
    if results.get("route_tables"):
        rt_file = f"{base_path}_route_tables.csv"
        fieldnames = ["AccountId", "AccountName", "Region", "RouteTableId", "RtName", "VpcId", "IsMain", "RoutesCount", "AssociatedSubnets", "SubnetIds"]
        with open(rt_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results["route_tables"])
        print(f"Route Tables CSV saved to: {rt_file}")

    # Write Security Groups
    if results.get("security_groups"):
        sg_file = f"{base_path}_security_groups.csv"
        fieldnames = ["AccountId", "AccountName", "Region", "SecurityGroupId", "GroupName", "VpcId", "Description", "InboundRulesCount", "OutboundRulesCount", "InUse", "UsedBy"]
        with open(sg_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results["security_groups"])
        print(f"Security Groups CSV saved to: {sg_file}")

    # Write VPC Endpoints
    if results.get("vpc_endpoints"):
        endpoint_file = f"{base_path}_endpoints.csv"
        fieldnames = ["AccountId", "AccountName", "Region", "VpcEndpointId", "EndpointName", "VpcId", "ServiceName", "EndpointType", "State", "HourlyCost", "MonthlyCost", "CreationTime"]
        with open(endpoint_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results["vpc_endpoints"])
        print(f"VPC Endpoints CSV saved to: {endpoint_file}")

    # Write VPC Peering
    if results.get("vpc_peering"):
        peering_file = f"{base_path}_peering.csv"
        fieldnames = ["AccountId", "AccountName", "Region", "PeeringConnectionId", "PeeringName", "RequesterVpcId", "RequesterCidr", "RequesterAccountId", "AccepterVpcId", "AccepterCidr", "AccepterAccountId", "Status"]
        with open(peering_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results["vpc_peering"])
        print(f"VPC Peering CSV saved to: {peering_file}")

    # Write Flow Logs
    if results.get("flow_logs"):
        flow_logs_file = f"{base_path}_flow_logs.csv"
        fieldnames = ["AccountId", "AccountName", "Region", "FlowLogId", "FlowLogName", "ResourceId", "ResourceType", "TrafficType", "Status", "DestinationType", "Destination", "CreationTime"]
        with open(flow_logs_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results["flow_logs"])
        print(f"Flow Logs CSV saved to: {flow_logs_file}")

    # Write Elastic IPs
    if results.get("elastic_ips"):
        eip_file = f"{base_path}_elastic_ips.csv"
        fieldnames = ["AccountId", "AccountName", "Region", "AllocationId", "PublicIp", "EipName", "PrivateIp", "AssociatedWith", "NatGatewayId", "Status", "HourlyCost", "MonthlyCost", "Domain", "NetworkBorderGroup"]
        with open(eip_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results["elastic_ips"])
        print(f"Elastic IPs CSV saved to: {eip_file}")

    # Write Transit Gateway Attachments
    if results.get("transit_gateway_attachments"):
        tgw_file = f"{base_path}_transit_gateway_attachments.csv"
        fieldnames = ["AccountId", "AccountName", "Region", "TransitGatewayAttachmentId", "TransitGatewayId", "TransitGatewayOwnerId", "ResourceOwnerId", "ResourceType", "ResourceId", "State", "AttachmentName", "HourlyCost", "MonthlyCost", "CreationTime"]
        with open(tgw_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results["transit_gateway_attachments"])
        print(f"Transit Gateway Attachments CSV saved to: {tgw_file}")


def write_html(results: dict, filepath: str):
    """Write results to HTML file with tabs for each resource type."""
    if not any(results.values()):
        print("No results to write to HTML.")
        return

    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS VPC Scan Report</title>
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
        .status-available, .status-attached, .status-active { color: #1d8102; font-weight: bold; }
        .status-pending { color: #ff9900; font-weight: bold; }
        .status-deleted, .status-detached, .status-failed { color: #d13212; font-weight: bold; }
        .yes { color: #1d8102; }
        .no { color: #879596; }
        .timestamp { color: #879596; font-size: 12px; margin-bottom: 20px; }
        .result-count { color: #666; font-size: 13px; margin-bottom: 10px; }
        /* Resizer handle */
        .resizer {
            position: absolute;
            right: 0;
            top: 0;
            height: 100%;
            width: 5px;
            cursor: col-resize;
            background: transparent;
        }
        .resizer:hover { background: rgba(255,153,0,0.5); }
    </style>
</head>
<body>
    <h1>AWS VPC Scan Report</h1>
    <p class="timestamp">Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>

    <div class="summary">
        <strong>Summary</strong>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="count">""" + str(len(set((v["AccountId"]) for v in results.get("vpcs", [])))) + """</div>
                <div class="label">Accounts</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("vpcs", []))) + """</div>
                <div class="label">VPCs</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("subnets", []))) + """</div>
                <div class="label">Subnets</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("internet_gateways", []))) + """</div>
                <div class="label">Internet GWs</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("nat_gateways", []))) + """</div>
                <div class="label">NAT GWs</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("security_groups", []))) + """</div>
                <div class="label">Security Groups</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("vpc_endpoints", []))) + """</div>
                <div class="label">VPC Endpoints</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("vpc_peering", []))) + """</div>
                <div class="label">Peering</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("flow_logs", []))) + """</div>
                <div class="label">Flow Logs</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("elastic_ips", []))) + """</div>
                <div class="label">Elastic IPs</div>
            </div>
            <div class="summary-item">
                <div class="count">""" + str(len(results.get("transit_gateway_attachments", []))) + """</div>
                <div class="label">TGW Attachments</div>
            </div>
        </div>
    </div>

    <div class="cost-summary">
        <strong>Estimated Monthly Costs</strong>
        <div class="cost-grid">
            <div class="cost-item">
                <div class="cost-value" id="natCost">$0.00</div>
                <div class="cost-label">NAT Gateways</div>
            </div>
            <div class="cost-item">
                <div class="cost-value" id="endpointCost">$0.00</div>
                <div class="cost-label">VPC Endpoints</div>
            </div>
            <div class="cost-item">
                <div class="cost-value" id="eipCost">$0.00</div>
                <div class="cost-label">Elastic IPs</div>
            </div>
            <div class="cost-item">
                <div class="cost-value" id="tgwCost">$0.00</div>
                <div class="cost-label">TGW Attachments</div>
            </div>
            <div class="cost-item cost-total">
                <div class="cost-value" id="totalCost">$0.00</div>
                <div class="cost-label">Total Monthly</div>
            </div>
        </div>
        <div class="cost-note">
            <strong>Note:</strong> Costs shown are on-demand pricing (us-east-1) based on AWS Price Calculator. Actual costs may be lower with volume discounts or enterprise agreements.<br>
            <strong>Data transfer charges (not included):</strong> NAT Gateway: $0.045/GB | VPC Peering: $0.01/GB (in &amp; out) | Transit Gateway: $0.02/GB | Internet Gateway: $0.09/GB (EC2 to internet) | Flow Logs: publishing &amp; storage costs
        </div>
    </div>

    <div class="tabs">
        <button class="tab active" onclick="showTab('vpcs')">VPCs (""" + str(len(results.get("vpcs", []))) + """)</button>
        <button class="tab" onclick="showTab('subnets')">Subnets (""" + str(len(results.get("subnets", []))) + """)</button>
        <button class="tab" onclick="showTab('igws')">Internet GWs (""" + str(len(results.get("internet_gateways", []))) + """)</button>
        <button class="tab" onclick="showTab('nats')">NAT GWs (""" + str(len(results.get("nat_gateways", []))) + """)</button>
        <button class="tab" onclick="showTab('rts')">Route Tables (""" + str(len(results.get("route_tables", []))) + """)</button>
        <button class="tab" onclick="showTab('sgs')">Security Groups (""" + str(len(results.get("security_groups", []))) + """)</button>
        <button class="tab" onclick="showTab('endpoints')">Endpoints (""" + str(len(results.get("vpc_endpoints", []))) + """)</button>
        <button class="tab" onclick="showTab('peering')">Peering (""" + str(len(results.get("vpc_peering", []))) + """)</button>
        <button class="tab" onclick="showTab('flowlogs')">Flow Logs (""" + str(len(results.get("flow_logs", []))) + """)</button>
        <button class="tab" onclick="showTab('eips')">Elastic IPs (""" + str(len(results.get("elastic_ips", []))) + """)</button>
        <button class="tab" onclick="showTab('tgw')">TGW Attachments (""" + str(len(results.get("transit_gateway_attachments", []))) + """)</button>
    </div>
"""

    # VPCs Tab
    html += """
    <div id="vpcs" class="tab-content active">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="vpcsSearch" placeholder="Search..." onkeyup="filterTable('vpcs')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="vpcsAccount" onchange="filterTable('vpcs')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="vpcsRegion" onchange="filterTable('vpcs')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Flow Logs</label>
                <select id="vpcsFlowLogs" onchange="filterTable('vpcs')">
                    <option value="">All</option>
                    <option value="Yes">Enabled</option>
                    <option value="No">Disabled</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('vpcs')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="vpcsCount">0</span> of """ + str(len(results.get("vpcs", []))) + """ VPCs</div>
        <div class="table-container">
        <table id="vpcsTable">
            <thead>
                <tr>
                    <th>Account ID</th>
                    <th>Account Name</th>
                    <th>Region</th>
                    <th>VPC ID</th>
                    <th>Name</th>
                    <th>CIDR Block</th>
                    <th>State</th>
                    <th>Flow Logs</th>
                </tr>
            </thead>
            <tbody>
"""
    for vpc in results.get("vpcs", []):
        state_class = "status-available" if vpc["State"] == "available" else ""
        flow_logs_class = "yes" if vpc["FlowLogsEnabled"] == "Yes" else "no"
        html += f"""                <tr>
                    <td>{vpc['AccountId']}</td>
                    <td>{vpc['AccountName']}</td>
                    <td>{vpc['Region']}</td>
                    <td>{vpc['VpcId']}</td>
                    <td>{vpc['VpcName']}</td>
                    <td>{vpc['CidrBlock']}</td>
                    <td class="{state_class}">{vpc['State']}</td>
                    <td class="{flow_logs_class}">{vpc['FlowLogsEnabled']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # Subnets Tab
    html += """
    <div id="subnets" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="subnetsSearch" placeholder="Search..." onkeyup="filterTable('subnets')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="subnetsAccount" onchange="filterTable('subnets')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="subnetsRegion" onchange="filterTable('subnets')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Public/Private</label>
                <select id="subnetsPublic" onchange="filterTable('subnets')">
                    <option value="">All</option>
                    <option value="Yes">Public</option>
                    <option value="No">Private</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('subnets')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="subnetsCount">0</span> of """ + str(len(results.get("subnets", []))) + """ Subnets</div>
        <div class="table-container">
        <table id="subnetsTable">
            <thead>
                <tr>
                    <th>Account ID</th>
                    <th>Account Name</th>
                    <th>Region</th>
                    <th>Subnet ID</th>
                    <th>Name</th>
                    <th>VPC ID</th>
                    <th>CIDR Block</th>
                    <th>AZ</th>
                    <th>Available IPs</th>
                    <th>Public</th>
                    <th>State</th>
                </tr>
            </thead>
            <tbody>
"""
    for subnet in results.get("subnets", []):
        public_class = "yes" if subnet["IsPublic"] == "Yes" else "no"
        state_class = "status-available" if subnet["State"] == "available" else ""
        html += f"""                <tr>
                    <td>{subnet['AccountId']}</td>
                    <td>{subnet['AccountName']}</td>
                    <td>{subnet['Region']}</td>
                    <td>{subnet['SubnetId']}</td>
                    <td>{subnet['SubnetName']}</td>
                    <td>{subnet['VpcId']}</td>
                    <td>{subnet['CidrBlock']}</td>
                    <td>{subnet['AvailabilityZone']}</td>
                    <td>{subnet['AvailableIps']}</td>
                    <td class="{public_class}">{subnet['IsPublic']}</td>
                    <td class="{state_class}">{subnet['State']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # Internet Gateways Tab
    html += """
    <div id="igws" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="igwsSearch" placeholder="Search..." onkeyup="filterTable('igws')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="igwsAccount" onchange="filterTable('igws')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="igwsRegion" onchange="filterTable('igws')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('igws')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="igwsCount">0</span> of """ + str(len(results.get("internet_gateways", []))) + """ Internet Gateways</div>
        <div class="table-container">
        <table id="igwsTable">
            <thead>
                <tr>
                    <th>Account ID</th>
                    <th>Account Name</th>
                    <th>Region</th>
                    <th>IGW ID</th>
                    <th>Name</th>
                    <th>VPC ID</th>
                    <th>State</th>
                </tr>
            </thead>
            <tbody>
"""
    for igw in results.get("internet_gateways", []):
        state_class = "status-available" if igw["State"] == "available" else "status-detached"
        html += f"""                <tr>
                    <td>{igw['AccountId']}</td>
                    <td>{igw['AccountName']}</td>
                    <td>{igw['Region']}</td>
                    <td>{igw['InternetGatewayId']}</td>
                    <td>{igw['IgwName']}</td>
                    <td>{igw['VpcId']}</td>
                    <td class="{state_class}">{igw['State']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # NAT Gateways Tab
    html += """
    <div id="nats" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="natsSearch" placeholder="Search..." onkeyup="filterTable('nats')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="natsAccount" onchange="filterTable('nats')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="natsRegion" onchange="filterTable('nats')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>State</label>
                <select id="natsState" onchange="filterTable('nats')">
                    <option value="">All States</option>
                    <option value="available">Available</option>
                    <option value="pending">Pending</option>
                    <option value="failed">Failed</option>
                    <option value="deleted">Deleted</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('nats')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="natsCount">0</span> of """ + str(len(results.get("nat_gateways", []))) + """ NAT Gateways</div>
        <div class="table-container">
        <table id="natsTable">
            <thead>
                <tr>
                    <th>Account ID</th>
                    <th>Account Name</th>
                    <th>Region</th>
                    <th>NAT Gateway ID</th>
                    <th>Name</th>
                    <th>VPC ID</th>
                    <th>Subnet ID</th>
                    <th>Availability</th>
                    <th>State</th>
                    <th>Type</th>
                    <th>Public IP</th>
                    <th>Hourly Cost</th>
                    <th>Monthly Cost</th>
                    <th>Created</th>
                </tr>
            </thead>
            <tbody>
"""
    for nat in results.get("nat_gateways", []):
        state_class = "status-available" if nat["State"] == "available" else ("status-pending" if nat["State"] == "pending" else "status-failed" if nat["State"] in ["failed", "deleted"] else "")
        html += f"""                <tr>
                    <td>{nat['AccountId']}</td>
                    <td>{nat['AccountName']}</td>
                    <td>{nat['Region']}</td>
                    <td>{nat['NatGatewayId']}</td>
                    <td>{nat['NatName']}</td>
                    <td>{nat['VpcId']}</td>
                    <td>{nat['SubnetId']}</td>
                    <td>{nat['Availability']}</td>
                    <td class="{state_class}">{nat['State']}</td>
                    <td>{nat['ConnectivityType']}</td>
                    <td>{nat['PublicIp']}</td>
                    <td>{nat['HourlyCost']}</td>
                    <td>{nat['MonthlyCost']}</td>
                    <td>{nat['CreateTime']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # Route Tables Tab
    html += """
    <div id="rts" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="rtsSearch" placeholder="Search..." onkeyup="filterTable('rts')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="rtsAccount" onchange="filterTable('rts')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="rtsRegion" onchange="filterTable('rts')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('rts')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="rtsCount">0</span> of """ + str(len(results.get("route_tables", []))) + """ Route Tables</div>
        <div class="table-container">
        <table id="rtsTable">
            <thead>
                <tr>
                    <th>Account ID</th>
                    <th>Account Name</th>
                    <th>Region</th>
                    <th>Route Table ID</th>
                    <th>Name</th>
                    <th>VPC ID</th>
                    <th>Main</th>
                    <th>Routes</th>
                    <th>Associated Subnets</th>
                </tr>
            </thead>
            <tbody>
"""
    for rt in results.get("route_tables", []):
        main_class = "yes" if rt["IsMain"] == "Yes" else "no"
        html += f"""                <tr>
                    <td>{rt['AccountId']}</td>
                    <td>{rt['AccountName']}</td>
                    <td>{rt['Region']}</td>
                    <td>{rt['RouteTableId']}</td>
                    <td>{rt['RtName']}</td>
                    <td>{rt['VpcId']}</td>
                    <td class="{main_class}">{rt['IsMain']}</td>
                    <td>{rt['RoutesCount']}</td>
                    <td>{rt['AssociatedSubnets']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # Security Groups Tab
    html += """
    <div id="sgs" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="sgsSearch" placeholder="Search..." onkeyup="filterTable('sgs')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="sgsAccount" onchange="filterTable('sgs')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="sgsRegion" onchange="filterTable('sgs')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>In Use</label>
                <select id="sgsInUse" onchange="filterTable('sgs')">
                    <option value="">All</option>
                    <option value="Yes">Yes</option>
                    <option value="No">No</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('sgs')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="sgsCount">0</span> of """ + str(len(results.get("security_groups", []))) + """ Security Groups</div>
        <div class="table-container">
        <table id="sgsTable">
            <thead>
                <tr>
                    <th>Account ID</th>
                    <th>Account Name</th>
                    <th>Region</th>
                    <th>Security Group ID</th>
                    <th>Security Group Name</th>
                    <th>VPC ID</th>
                    <th>Description</th>
                    <th>Inbound Rules</th>
                    <th>Outbound Rules</th>
                    <th>In Use</th>
                    <th>Used By</th>
                </tr>
            </thead>
            <tbody>
"""
    for sg in results.get("security_groups", []):
        in_use_class = "yes" if sg["InUse"] == "Yes" else "no"
        html += f"""                <tr>
                    <td>{sg['AccountId']}</td>
                    <td>{sg['AccountName']}</td>
                    <td>{sg['Region']}</td>
                    <td>{sg['SecurityGroupId']}</td>
                    <td>{sg['GroupName']}</td>
                    <td>{sg['VpcId']}</td>
                    <td>{sg['Description']}</td>
                    <td>{sg['InboundRulesCount']}</td>
                    <td>{sg['OutboundRulesCount']}</td>
                    <td class="{in_use_class}">{sg['InUse']}</td>
                    <td>{sg['UsedBy']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # VPC Endpoints Tab
    html += """
    <div id="endpoints" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="endpointsSearch" placeholder="Search..." onkeyup="filterTable('endpoints')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="endpointsAccount" onchange="filterTable('endpoints')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="endpointsRegion" onchange="filterTable('endpoints')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Type</label>
                <select id="endpointsType" onchange="filterTable('endpoints')">
                    <option value="">All Types</option>
                    <option value="Gateway">Gateway</option>
                    <option value="Interface">Interface</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('endpoints')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="endpointsCount">0</span> of """ + str(len(results.get("vpc_endpoints", []))) + """ VPC Endpoints</div>
        <div class="table-container">
        <table id="endpointsTable">
            <thead>
                <tr>
                    <th>Account ID</th>
                    <th>Account Name</th>
                    <th>Region</th>
                    <th>Endpoint ID</th>
                    <th>Name</th>
                    <th>VPC ID</th>
                    <th>Service Name</th>
                    <th>Type</th>
                    <th>State</th>
                    <th>Hourly Cost</th>
                    <th>Monthly Cost</th>
                    <th>Created</th>
                </tr>
            </thead>
            <tbody>
"""
    for endpoint in results.get("vpc_endpoints", []):
        state_class = "status-available" if endpoint["State"] == "available" else ("status-pending" if endpoint["State"] == "pending" else "")
        html += f"""                <tr>
                    <td>{endpoint['AccountId']}</td>
                    <td>{endpoint['AccountName']}</td>
                    <td>{endpoint['Region']}</td>
                    <td>{endpoint['VpcEndpointId']}</td>
                    <td>{endpoint['EndpointName']}</td>
                    <td>{endpoint['VpcId']}</td>
                    <td>{endpoint['ServiceName']}</td>
                    <td>{endpoint['EndpointType']}</td>
                    <td class="{state_class}">{endpoint['State']}</td>
                    <td>{endpoint['HourlyCost']}</td>
                    <td>{endpoint['MonthlyCost']}</td>
                    <td>{endpoint['CreationTime']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # VPC Peering Tab
    html += """
    <div id="peering" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="peeringSearch" placeholder="Search..." onkeyup="filterTable('peering')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="peeringAccount" onchange="filterTable('peering')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="peeringRegion" onchange="filterTable('peering')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Status</label>
                <select id="peeringStatus" onchange="filterTable('peering')">
                    <option value="">All</option>
                    <option value="active">Active</option>
                    <option value="pending-acceptance">Pending</option>
                    <option value="deleted">Deleted</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('peering')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="peeringCount">0</span> of """ + str(len(results.get("vpc_peering", []))) + """ Peering Connections</div>
        <div class="table-container">
        <table id="peeringTable">
            <thead>
                <tr>
                    <th>Account ID</th>
                    <th>Account Name</th>
                    <th>Region</th>
                    <th>Peering ID</th>
                    <th>Name</th>
                    <th>Requester VPC</th>
                    <th>Requester CIDR</th>
                    <th>Accepter VPC</th>
                    <th>Accepter CIDR</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
"""
    for peering in results.get("vpc_peering", []):
        status_class = "status-active" if peering["Status"] == "active" else ("status-pending" if "pending" in peering["Status"] else "status-deleted" if peering["Status"] == "deleted" else "")
        html += f"""                <tr>
                    <td>{peering['AccountId']}</td>
                    <td>{peering['AccountName']}</td>
                    <td>{peering['Region']}</td>
                    <td>{peering['PeeringConnectionId']}</td>
                    <td>{peering['PeeringName']}</td>
                    <td>{peering['RequesterVpcId']}</td>
                    <td>{peering['RequesterCidr']}</td>
                    <td>{peering['AccepterVpcId']}</td>
                    <td>{peering['AccepterCidr']}</td>
                    <td class="{status_class}">{peering['Status']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # Flow Logs Tab
    html += """
    <div id="flowlogs" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="flowlogsSearch" placeholder="Search..." onkeyup="filterTable('flowlogs')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="flowlogsAccount" onchange="filterTable('flowlogs')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="flowlogsRegion" onchange="filterTable('flowlogs')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Resource Type</label>
                <select id="flowlogsResourceType" onchange="filterTable('flowlogs')">
                    <option value="">All Types</option>
                    <option value="VPC">VPC</option>
                    <option value="Subnet">Subnet</option>
                    <option value="NetworkInterface">ENI</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Destination</label>
                <select id="flowlogsDestType" onchange="filterTable('flowlogs')">
                    <option value="">All</option>
                    <option value="cloud-watch-logs">CloudWatch</option>
                    <option value="s3">S3</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('flowlogs')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="flowlogsCount">0</span> of """ + str(len(results.get("flow_logs", []))) + """ Flow Logs</div>
        <div class="table-container">
        <table id="flowlogsTable">
            <thead>
                <tr>
                    <th>Account ID</th>
                    <th>Account Name</th>
                    <th>Region</th>
                    <th>Flow Log ID</th>
                    <th>Name</th>
                    <th>Resource ID</th>
                    <th>Resource Type</th>
                    <th>Traffic Type</th>
                    <th>Status</th>
                    <th>Destination Type</th>
                    <th>Destination</th>
                    <th>Created</th>
                </tr>
            </thead>
            <tbody>
"""
    for fl in results.get("flow_logs", []):
        status_class = "status-active" if fl["Status"] == "ACTIVE" else ""
        html += f"""                <tr>
                    <td>{fl['AccountId']}</td>
                    <td>{fl['AccountName']}</td>
                    <td>{fl['Region']}</td>
                    <td>{fl['FlowLogId']}</td>
                    <td>{fl['FlowLogName']}</td>
                    <td>{fl['ResourceId']}</td>
                    <td>{fl['ResourceType']}</td>
                    <td>{fl['TrafficType']}</td>
                    <td class="{status_class}">{fl['Status']}</td>
                    <td>{fl['DestinationType']}</td>
                    <td>{fl['Destination']}</td>
                    <td>{fl['CreationTime']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # Elastic IPs Tab
    html += """
    <div id="eips" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="eipsSearch" placeholder="Search..." onkeyup="filterTable('eips')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="eipsAccount" onchange="filterTable('eips')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="eipsRegion" onchange="filterTable('eips')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Status</label>
                <select id="eipsStatus" onchange="filterTable('eips')">
                    <option value="">All</option>
                    <option value="Associated">Associated</option>
                    <option value="Available">Available</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('eips')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="eipsCount">0</span> of """ + str(len(results.get("elastic_ips", []))) + """ Elastic IPs</div>
        <div class="table-container">
        <table id="eipsTable">
            <thead>
                <tr>
                    <th>Account ID</th>
                    <th>Account Name</th>
                    <th>Region</th>
                    <th>Allocation ID</th>
                    <th>Public IP</th>
                    <th>Name</th>
                    <th>Private IP</th>
                    <th>Associated With</th>
                    <th>NAT Gateway</th>
                    <th>Status</th>
                    <th>Hourly Cost</th>
                    <th>Monthly Cost</th>
                    <th>Domain</th>
                    <th>Network Border Group</th>
                </tr>
            </thead>
            <tbody>
"""
    for eip in results.get("elastic_ips", []):
        status_class = "status-available" if eip["Status"] == "Associated" else "no"
        nat_class = "yes" if eip["NatGatewayId"] != "N/A" else "no"
        html += f"""                <tr>
                    <td>{eip['AccountId']}</td>
                    <td>{eip['AccountName']}</td>
                    <td>{eip['Region']}</td>
                    <td>{eip['AllocationId']}</td>
                    <td>{eip['PublicIp']}</td>
                    <td>{eip['EipName']}</td>
                    <td>{eip['PrivateIp']}</td>
                    <td>{eip['AssociatedWith']}</td>
                    <td class="{nat_class}">{eip['NatGatewayId']}</td>
                    <td class="{status_class}">{eip['Status']}</td>
                    <td>{eip['HourlyCost']}</td>
                    <td>{eip['MonthlyCost']}</td>
                    <td>{eip['Domain']}</td>
                    <td>{eip['NetworkBorderGroup']}</td>
                </tr>
"""
    html += """            </tbody>
        </table>
        </div>
    </div>
"""

    # Transit Gateway Attachments Tab
    html += """
    <div id="tgw" class="tab-content">
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" id="tgwSearch" placeholder="Search..." onkeyup="filterTable('tgw')">
            </div>
            <div class="filter-group">
                <label>Account</label>
                <select id="tgwAccount" onchange="filterTable('tgw')">
                    <option value="">All Accounts</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Region</label>
                <select id="tgwRegion" onchange="filterTable('tgw')">
                    <option value="">All Regions</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Resource Type</label>
                <select id="tgwResourceType" onchange="filterTable('tgw')">
                    <option value="">All Types</option>
                    <option value="vpc">VPC</option>
                    <option value="vpn">VPN</option>
                    <option value="direct-connect-gateway">Direct Connect</option>
                    <option value="peering">Peering</option>
                    <option value="connect">Connect</option>
                </select>
            </div>
            <div class="filter-group">
                <label>State</label>
                <select id="tgwState" onchange="filterTable('tgw')">
                    <option value="">All</option>
                    <option value="available">Available</option>
                    <option value="pending">Pending</option>
                    <option value="deleting">Deleting</option>
                    <option value="deleted">Deleted</option>
                </select>
            </div>
            <button class="btn-clear" onclick="clearFilters('tgw')">Clear</button>
        </div>
        <div class="result-count">Showing <span id="tgwCount">0</span> of """ + str(len(results.get("transit_gateway_attachments", []))) + """ TGW Attachments</div>
        <div class="table-container">
        <table id="tgwTable">
            <thead>
                <tr>
                    <th>Account ID</th>
                    <th>Account Name</th>
                    <th>Region</th>
                    <th>Attachment ID</th>
                    <th>Transit Gateway ID</th>
                    <th>TGW Owner</th>
                    <th>Resource Owner</th>
                    <th>Resource Type</th>
                    <th>Resource ID</th>
                    <th>State</th>
                    <th>Name</th>
                    <th>Hourly Cost</th>
                    <th>Monthly Cost</th>
                    <th>Created</th>
                </tr>
            </thead>
            <tbody>
"""
    for tgw_att in results.get("transit_gateway_attachments", []):
        state_class = "status-available" if tgw_att["State"] == "available" else "no"
        html += f"""                <tr>
                    <td>{tgw_att['AccountId']}</td>
                    <td>{tgw_att['AccountName']}</td>
                    <td>{tgw_att['Region']}</td>
                    <td>{tgw_att['TransitGatewayAttachmentId']}</td>
                    <td>{tgw_att['TransitGatewayId']}</td>
                    <td>{tgw_att['TransitGatewayOwnerId']}</td>
                    <td>{tgw_att['ResourceOwnerId']}</td>
                    <td>{tgw_att['ResourceType']}</td>
                    <td>{tgw_att['ResourceId']}</td>
                    <td class="{state_class}">{tgw_att['State']}</td>
                    <td>{tgw_att['AttachmentName']}</td>
                    <td>{tgw_att['HourlyCost']}</td>
                    <td>{tgw_att['MonthlyCost']}</td>
                    <td>{tgw_att['CreationTime']}</td>
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
    let natTotal = 0;
    let endpointTotal = 0;
    let eipTotal = 0;
    let tgwTotal = 0;

    // Calculate NAT Gateway costs (MonthlyCost is column 12)
    const natsTable = document.getElementById('natsTable');
    if (natsTable) {
        const rows = natsTable.querySelectorAll('tbody tr');
        rows.forEach(row => {
            if (!row.classList.contains('hidden')) {
                const costCell = row.cells[12];
                if (costCell) {
                    const cost = parseFloat(costCell.textContent.replace('$', '').replace(',', '')) || 0;
                    natTotal += cost;
                }
            }
        });
    }

    // Calculate VPC Endpoint costs (MonthlyCost is column 10)
    const endpointsTable = document.getElementById('endpointsTable');
    if (endpointsTable) {
        const rows = endpointsTable.querySelectorAll('tbody tr');
        rows.forEach(row => {
            if (!row.classList.contains('hidden')) {
                const costCell = row.cells[10];
                if (costCell) {
                    const cost = parseFloat(costCell.textContent.replace('$', '').replace(',', '')) || 0;
                    endpointTotal += cost;
                }
            }
        });
    }

    // Calculate Elastic IP costs (MonthlyCost is column 11)
    const eipsTable = document.getElementById('eipsTable');
    if (eipsTable) {
        const rows = eipsTable.querySelectorAll('tbody tr');
        rows.forEach(row => {
            if (!row.classList.contains('hidden')) {
                const costCell = row.cells[11];
                if (costCell) {
                    const cost = parseFloat(costCell.textContent.replace('$', '').replace(',', '')) || 0;
                    eipTotal += cost;
                }
            }
        });
    }

    // Calculate Transit Gateway Attachment costs (MonthlyCost is column 12)
    const tgwTable = document.getElementById('tgwTable');
    if (tgwTable) {
        const rows = tgwTable.querySelectorAll('tbody tr');
        rows.forEach(row => {
            if (!row.classList.contains('hidden')) {
                const costCell = row.cells[12];
                if (costCell) {
                    const cost = parseFloat(costCell.textContent.replace('$', '').replace(',', '')) || 0;
                    tgwTotal += cost;
                }
            }
        });
    }

    // Update the display with formatted numbers
    const formatCost = (cost) => '$' + cost.toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2});
    const totalCost = natTotal + endpointTotal + eipTotal + tgwTotal;
    document.getElementById('natCost').textContent = formatCost(natTotal);
    document.getElementById('endpointCost').textContent = formatCost(endpointTotal);
    document.getElementById('eipCost').textContent = formatCost(eipTotal);
    document.getElementById('tgwCost').textContent = formatCost(tgwTotal);
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
    const tabs = ['vpcs', 'subnets', 'igws', 'nats', 'rts', 'sgs', 'endpoints', 'peering', 'flowlogs', 'eips', 'tgw'];
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
    if (tabId === 'vpcs') {
        const flowLogsSelect = document.getElementById('vpcsFlowLogs');
        extraFilter = flowLogsSelect ? flowLogsSelect.value : '';
    } else if (tabId === 'subnets') {
        const publicSelect = document.getElementById('subnetsPublic');
        extraFilter = publicSelect ? publicSelect.value : '';
    } else if (tabId === 'nats') {
        const stateSelect = document.getElementById('natsState');
        extraFilter = stateSelect ? stateSelect.value : '';
    } else if (tabId === 'sgs') {
        const inUseSelect = document.getElementById('sgsInUse');
        extraFilter = inUseSelect ? inUseSelect.value : '';
    } else if (tabId === 'endpoints') {
        const typeSelect = document.getElementById('endpointsType');
        extraFilter = typeSelect ? typeSelect.value : '';
    } else if (tabId === 'peering') {
        const statusSelect = document.getElementById('peeringStatus');
        extraFilter = statusSelect ? statusSelect.value : '';
    } else if (tabId === 'flowlogs') {
        const resourceTypeSelect = document.getElementById('flowlogsResourceType');
        extraFilter = resourceTypeSelect ? resourceTypeSelect.value : '';
    } else if (tabId === 'eips') {
        const statusSelect = document.getElementById('eipsStatus');
        extraFilter = statusSelect ? statusSelect.value : '';
    } else if (tabId === 'tgw') {
        const resourceTypeSelect = document.getElementById('tgwResourceType');
        extraFilter = resourceTypeSelect ? resourceTypeSelect.value : '';
    }

    // Get second extra filter for flowlogs and tgw
    let extraFilter2 = '';
    if (tabId === 'flowlogs') {
        const destTypeSelect = document.getElementById('flowlogsDestType');
        extraFilter2 = destTypeSelect ? destTypeSelect.value : '';
    } else if (tabId === 'tgw') {
        const stateSelect = document.getElementById('tgwState');
        extraFilter2 = stateSelect ? stateSelect.value : '';
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
            if (tabId === 'vpcs') {
                const flowLogs = row.cells[7].textContent;
                if (flowLogs !== extraFilter) show = false;
            } else if (tabId === 'subnets') {
                const isPublic = row.cells[9].textContent;
                if (isPublic !== extraFilter) show = false;
            } else if (tabId === 'nats') {
                const state = row.cells[8].textContent;
                if (state !== extraFilter) show = false;
            } else if (tabId === 'sgs') {
                const inUse = row.cells[9].textContent;
                if (inUse !== extraFilter) show = false;
            } else if (tabId === 'endpoints') {
                const type = row.cells[7].textContent;
                if (type !== extraFilter) show = false;
            } else if (tabId === 'peering') {
                const status = row.cells[9].textContent;
                if (status !== extraFilter) show = false;
            } else if (tabId === 'flowlogs') {
                const resourceType = row.cells[6].textContent;
                if (resourceType !== extraFilter) show = false;
            } else if (tabId === 'eips') {
                const status = row.cells[9].textContent;
                if (status !== extraFilter) show = false;
            } else if (tabId === 'tgw') {
                const resourceType = row.cells[7].textContent;
                if (resourceType !== extraFilter) show = false;
            }
        }

        // Second extra filter for flowlogs (destination type) and tgw (state)
        if (extraFilter2 && tabId === 'flowlogs') {
            const destType = row.cells[9].textContent;
            if (destType !== extraFilter2) show = false;
        }
        if (extraFilter2 && tabId === 'tgw') {
            const state = row.cells[9].textContent;
            if (state !== extraFilter2) show = false;
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
    if (tabId === 'vpcs') {
        document.getElementById('vpcsFlowLogs').value = '';
    } else if (tabId === 'subnets') {
        document.getElementById('subnetsPublic').value = '';
    } else if (tabId === 'nats') {
        document.getElementById('natsState').value = '';
    } else if (tabId === 'sgs') {
        document.getElementById('sgsInUse').value = '';
    } else if (tabId === 'endpoints') {
        document.getElementById('endpointsType').value = '';
    } else if (tabId === 'peering') {
        document.getElementById('peeringStatus').value = '';
    } else if (tabId === 'flowlogs') {
        document.getElementById('flowlogsResourceType').value = '';
        document.getElementById('flowlogsDestType').value = '';
    } else if (tabId === 'eips') {
        document.getElementById('eipsStatus').value = '';
    } else if (tabId === 'tgw') {
        document.getElementById('tgwResourceType').value = '';
        document.getElementById('tgwState').value = '';
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
    let direction = 'asc';
    if (isAsc) {
        direction = 'desc';
        th.classList.add('sort-desc');
    } else {
        th.classList.add('sort-asc');
    }

    // Sort rows
    rows.sort((a, b) => {
        let aVal = a.cells[colIndex].textContent.trim();
        let bVal = b.cells[colIndex].textContent.trim();

        // Try numeric sort first
        const aNum = parseFloat(aVal.replace(/,/g, ''));
        const bNum = parseFloat(bVal.replace(/,/g, ''));

        if (!isNaN(aNum) && !isNaN(bNum)) {
            return direction === 'asc' ? aNum - bNum : bNum - aNum;
        }

        // Fall back to string sort
        aVal = aVal.toLowerCase();
        bVal = bVal.toLowerCase();

        if (direction === 'asc') {
            return aVal.localeCompare(bVal);
        } else {
            return bVal.localeCompare(aVal);
        }
    });

    // Re-append sorted rows
    rows.forEach(row => tbody.appendChild(row));
}

// Initialize sorting on all table headers
function initSorting() {
    document.querySelectorAll('table').forEach(table => {
        const headers = table.querySelectorAll('th');
        headers.forEach((th, index) => {
            // Add sort icon span if not present
            if (!th.querySelector('.sort-icon')) {
                const icon = document.createElement('span');
                icon.className = 'sort-icon';
                th.appendChild(icon);
            }

            th.addEventListener('click', () => {
                sortTable(table.id, index);
            });
        });
    });
}

// Column resizing functionality
function initResizableColumns() {
    document.querySelectorAll('table').forEach(table => {
        const headers = table.querySelectorAll('th');
        headers.forEach(th => {
            const handle = document.createElement('div');
            handle.className = 'resize-handle';
            th.appendChild(handle);

            let startX, startWidth;

            handle.addEventListener('mousedown', (e) => {
                e.stopPropagation();
                startX = e.pageX;
                startWidth = th.offsetWidth;

                const onMouseMove = (e) => {
                    const width = startWidth + (e.pageX - startX);
                    if (width >= 60) {
                        th.style.width = width + 'px';
                        th.style.minWidth = width + 'px';
                    }
                };

                const onMouseUp = () => {
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
populateFilters();
filterTable('vpcs');
initSorting();
initResizableColumns();
updateCosts();
</script>
</body>
</html>
"""

    with open(filepath, "w") as f:
        f.write(html)

    print(f"\nHTML report saved to: {filepath}")


def write_json(results: dict, filepath: str, summary: dict):
    """Write results to JSON file."""
    output_data = {
        "timestamp": datetime.now().isoformat(),
        "summary": summary,
        "results": results,
    }

    with open(filepath, "w") as f:
        json.dump(output_data, f, indent=2, default=str)

    print(f"\nJSON report saved to: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="Scan AWS VPC resources across multiple accounts and regions"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output results to JSON file"
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="Output results to CSV files (creates multiple files with prefix)"
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Output results to HTML file"
    )
    parser.add_argument(
        "--profile",
        help="Scan only a specific AWS profile"
    )
    parser.add_argument(
        "--profile-pattern",
        default=".admin",
        help="Pattern to match AWS profiles (default: .admin)"
    )
    parser.add_argument(
        "--regions",
        default="us-east-1,us-west-2",
        help="Comma-separated list of regions to scan (default: us-east-1,us-west-2)"
    )

    args = parser.parse_args()

    # Parse regions
    regions = [r.strip() for r in args.regions.split(",")]

    # Get profiles to scan
    if args.profile:
        # For single profile, try to get account name from config
        all_profiles = get_aws_profiles("")  # Get all profiles to find account name
        account_name = all_profiles.get(args.profile, args.profile)
        profiles = {args.profile: account_name}
    else:
        profiles = get_aws_profiles(args.profile_pattern)

    if not profiles:
        print(f"No AWS profiles found matching pattern '{args.profile_pattern}'")
        sys.exit(1)

    print(f"Found {len(profiles)} profile(s) to scan")
    print(f"Regions: {', '.join(regions)}")
    print(f"{'='*60}")

    all_results = {
        "vpcs": [],
        "subnets": [],
        "internet_gateways": [],
        "nat_gateways": [],
        "route_tables": [],
        "security_groups": [],
        "vpc_endpoints": [],
        "vpc_peering": [],
        "flow_logs": [],
        "elastic_ips": [],
        "transit_gateway_attachments": [],
    }
    accounts_scanned = 0
    accounts_failed = 0

    for i, (profile, account_name) in enumerate(profiles.items(), 1):
        print(f"[{i}/{len(profiles)}] Scanning profile: {profile} ({account_name})")

        results = scan_account(profile, account_name, regions, args.verbose)

        if any(results.values()):
            for key in all_results:
                all_results[key].extend(results.get(key, []))
            accounts_scanned += 1
        else:
            accounts_failed += 1

    # Summary
    summary = {
        "profiles_attempted": len(profiles),
        "accounts_scanned": accounts_scanned,
        "accounts_failed": accounts_failed,
        "regions_scanned": regions,
        "total_vpcs": len(all_results["vpcs"]),
        "total_subnets": len(all_results["subnets"]),
        "total_internet_gateways": len(all_results["internet_gateways"]),
        "total_nat_gateways": len(all_results["nat_gateways"]),
        "total_route_tables": len(all_results["route_tables"]),
        "total_security_groups": len(all_results["security_groups"]),
        "total_vpc_endpoints": len(all_results["vpc_endpoints"]),
        "total_vpc_peering": len(all_results["vpc_peering"]),
        "total_flow_logs": len(all_results["flow_logs"]),
        "total_elastic_ips": len(all_results["elastic_ips"]),
    }

    # Print summary
    print(f"\n{'='*60}")
    print("SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Profiles attempted: {summary['profiles_attempted']}")
    print(f"Accounts scanned: {summary['accounts_scanned']}")
    print(f"Accounts failed: {summary['accounts_failed']}")
    print(f"Regions scanned: {', '.join(summary['regions_scanned'])}")
    print(f"\nResources Found:")
    print(f"  VPCs: {summary['total_vpcs']}")
    print(f"  Subnets: {summary['total_subnets']}")
    print(f"  Internet Gateways: {summary['total_internet_gateways']}")
    print(f"  NAT Gateways: {summary['total_nat_gateways']}")
    print(f"  Route Tables: {summary['total_route_tables']}")
    print(f"  Security Groups: {summary['total_security_groups']}")
    print(f"  VPC Endpoints: {summary['total_vpc_endpoints']}")
    print(f"  VPC Peering: {summary['total_vpc_peering']}")
    print(f"  Flow Logs: {summary['total_flow_logs']}")
    print(f"  Elastic IPs: {summary['total_elastic_ips']}")

    # Print detailed report if verbose
    if args.verbose:
        print_report(all_results, args.verbose)

    # Output files
    if args.csv:
        write_csv(all_results, args.csv)

    if args.html:
        write_html(all_results, args.html)

    if args.output:
        write_json(all_results, args.output, summary)


if __name__ == "__main__":
    main()
