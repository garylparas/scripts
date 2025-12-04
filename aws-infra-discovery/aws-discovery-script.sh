#!/bin/bash
# AWS Infrastructure Discovery Script for JobTarget DNS Setup
# This script gathers all necessary information about your AWS infrastructure

set -e

# Output file
OUTPUT_FILE="aws-infrastructure-discovery-$(date +%Y%m%d-%H%M%S).txt"

echo "==================================================" | tee -a $OUTPUT_FILE
echo "AWS Infrastructure Discovery for JobTarget DNS" | tee -a $OUTPUT_FILE
echo "Generated: $(date)" | tee -a $OUTPUT_FILE
echo "==================================================" | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE

# Account profiles
INFRA_CORE="infra-core.admin"
INFRA_PROD_NET="infra-prod-network.admin"
LEGACY_PROD="legacy-prod.admin"
INFRA_DEV_NET="infra-dev-network.admin"

# Function to run command with error handling
run_command() {
    local profile=$1
    local description=$2
    shift 2
    
    echo "" | tee -a $OUTPUT_FILE
    echo "========================================" | tee -a $OUTPUT_FILE
    echo "$description" | tee -a $OUTPUT_FILE
    echo "Profile: $profile" | tee -a $OUTPUT_FILE
    echo "========================================" | tee -a $OUTPUT_FILE
    
    if "$@" --profile $profile >> $OUTPUT_FILE 2>&1; then
        echo "✅ Success" | tee -a $OUTPUT_FILE
    else
        echo "⚠️ Failed or No Data" | tee -a $OUTPUT_FILE
    fi
}

# ========================================
# Section 1: Infra-Core Account
# ========================================
echo "" | tee -a $OUTPUT_FILE
echo "###################################################" | tee -a $OUTPUT_FILE
echo "# INFRA-CORE ACCOUNT (467116115043)" | tee -a $OUTPUT_FILE
echo "###################################################" | tee -a $OUTPUT_FILE

# Get account ID
run_command $INFRA_CORE "1.1 Account Identity" \
    aws sts get-caller-identity

# List all VPCs
run_command $INFRA_CORE "1.2 All VPCs" \
    aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,CidrBlock,Tags[?Key==`Name`].Value|[0],IsDefault]' --output table

# VPC DNS settings
echo "" | tee -a $OUTPUT_FILE
echo "1.3 VPC DNS Attributes for vpc-08fcc16df5104273f" | tee -a $OUTPUT_FILE
aws ec2 describe-vpc-attribute --vpc-id vpc-08fcc16df5104273f --attribute enableDnsSupport --profile $INFRA_CORE >> $OUTPUT_FILE 2>&1
aws ec2 describe-vpc-attribute --vpc-id vpc-08fcc16df5104273f --attribute enableDnsHostnames --profile $INFRA_CORE >> $OUTPUT_FILE 2>&1

# Resolver Endpoints
run_command $INFRA_CORE "1.4 Resolver Endpoints" \
    aws route53resolver list-resolver-endpoints

# Get Inbound Endpoint Details
run_command $INFRA_CORE "1.5 Inbound Endpoint Details (rslvr-in-961cf073fb1d46f09)" \
    aws route53resolver get-resolver-endpoint --resolver-endpoint-id rslvr-in-961cf073fb1d46f09

# Security groups on inbound endpoint
echo "" | tee -a $OUTPUT_FILE
echo "1.6 Security Group Rules for Inbound Endpoint" | tee -a $OUTPUT_FILE
INBOUND_SG=$(aws route53resolver get-resolver-endpoint --resolver-endpoint-id rslvr-in-961cf073fb1d46f09 --profile $INFRA_CORE --query 'ResolverEndpoint.SecurityGroupIds[0]' --output text 2>/dev/null)
if [ ! -z "$INBOUND_SG" ]; then
    aws ec2 describe-security-groups --group-ids $INBOUND_SG --profile $INFRA_CORE >> $OUTPUT_FILE 2>&1
fi

# Resolver Rules
run_command $INFRA_CORE "1.7 Resolver Rules" \
    aws route53resolver list-resolver-rules

# Private Hosted Zones
run_command $INFRA_CORE "1.8 Private Hosted Zones" \
    aws route53 list-hosted-zones --query 'HostedZones[?Config.PrivateZone==`true`]'

# Transit Gateway Attachments
run_command $INFRA_CORE "1.9 Transit Gateway VPC Attachments" \
    aws ec2 describe-transit-gateway-vpc-attachments --query 'TransitGatewayVpcAttachments[*].[TransitGatewayAttachmentId,VpcId,State,TransitGatewayId]' --output table

# ========================================
# Section 2: Infra-Prod-Network Account
# ========================================
echo "" | tee -a $OUTPUT_FILE
echo "###################################################" | tee -a $OUTPUT_FILE
echo "# INFRA-PROD-NETWORK ACCOUNT (853191814192)" | tee -a $OUTPUT_FILE
echo "###################################################" | tee -a $OUTPUT_FILE

run_command $INFRA_PROD_NET "2.1 Account Identity" \
    aws sts get-caller-identity

run_command $INFRA_PROD_NET "2.2 All VPCs" \
    aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,CidrBlock,Tags[?Key==`Name`].Value|[0],IsDefault]' --output table

# VPC DNS settings
echo "" | tee -a $OUTPUT_FILE
echo "2.3 VPC DNS Attributes for vpc-0c7da945d03a3948c" | tee -a $OUTPUT_FILE
aws ec2 describe-vpc-attribute --vpc-id vpc-0c7da945d03a3948c --attribute enableDnsSupport --profile $INFRA_PROD_NET >> $OUTPUT_FILE 2>&1
aws ec2 describe-vpc-attribute --vpc-id vpc-0c7da945d03a3948c --attribute enableDnsHostnames --profile $INFRA_PROD_NET >> $OUTPUT_FILE 2>&1

run_command $INFRA_PROD_NET "2.4 Resolver Endpoints" \
    aws route53resolver list-resolver-endpoints

# Get Outbound Endpoint Details
run_command $INFRA_PROD_NET "2.5 Outbound Endpoint Details (rslvr-out-c98a45eed0be4b0fa)" \
    aws route53resolver get-resolver-endpoint --resolver-endpoint-id rslvr-out-c98a45eed0be4b0fa

run_command $INFRA_PROD_NET "2.6 Resolver Rules" \
    aws route53resolver list-resolver-rules

# Get the specific resolver rule details
run_command $INFRA_PROD_NET "2.7 Resolver Rule Details (rslvr-rr-84abe9b9dc3d43dda)" \
    aws route53resolver get-resolver-rule --resolver-rule-id rslvr-rr-84abe9b9dc3d43dda

# Resolver Rule Associations
run_command $INFRA_PROD_NET "2.8 Resolver Rule Associations" \
    aws route53resolver list-resolver-rule-associations --query 'ResolverRuleAssociations[*].[ResolverRuleId,VPCId,Name]' --output table

# RAM Resource Shares (for shared resolver rules)
run_command $INFRA_PROD_NET "2.9 RAM Resource Shares (Owned)" \
    aws ram get-resource-shares --resource-owner SELF --query 'resourceShares[*].[name,resourceShareArn,status]' --output table

run_command $INFRA_PROD_NET "2.10 Private Hosted Zones" \
    aws route53 list-hosted-zones --query 'HostedZones[?Config.PrivateZone==`true`]'

run_command $INFRA_PROD_NET "2.11 Transit Gateway VPC Attachments" \
    aws ec2 describe-transit-gateway-vpc-attachments --query 'TransitGatewayVpcAttachments[*].[TransitGatewayAttachmentId,VpcId,State,TransitGatewayId]' --output table

# ========================================
# Section 3: Legacy-Prod Account
# ========================================
echo "" | tee -a $OUTPUT_FILE
echo "###################################################" | tee -a $OUTPUT_FILE
echo "# LEGACY-PROD ACCOUNT (481411744724)" | tee -a $OUTPUT_FILE
echo "###################################################" | tee -a $OUTPUT_FILE

run_command $LEGACY_PROD "3.1 Account Identity" \
    aws sts get-caller-identity

run_command $LEGACY_PROD "3.2 All VPCs" \
    aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,CidrBlock,Tags[?Key==`Name`].Value|[0],IsDefault]' --output table

# VPC DNS settings
echo "" | tee -a $OUTPUT_FILE
echo "3.3 VPC DNS Attributes for vpc-0510921e656098c92" | tee -a $OUTPUT_FILE
aws ec2 describe-vpc-attribute --vpc-id vpc-0510921e656098c92 --attribute enableDnsSupport --profile $LEGACY_PROD >> $OUTPUT_FILE 2>&1
aws ec2 describe-vpc-attribute --vpc-id vpc-0510921e656098c92 --attribute enableDnsHostnames --profile $LEGACY_PROD >> $OUTPUT_FILE 2>&1

run_command $LEGACY_PROD "3.4 Resolver Rule Associations" \
    aws route53resolver list-resolver-rule-associations --query 'ResolverRuleAssociations[*].[ResolverRuleId,VPCId,Name]' --output table

# RAM Resource Shares (received)
run_command $LEGACY_PROD "3.5 RAM Resource Shares (Shared With Me)" \
    aws ram get-resource-shares --resource-owner OTHER-ACCOUNTS --query 'resourceShares[*].[name,resourceShareArn,status]' --output table

run_command $LEGACY_PROD "3.6 Private Hosted Zones" \
    aws route53 list-hosted-zones --query 'HostedZones[?Config.PrivateZone==`true`]'

run_command $LEGACY_PROD "3.7 Transit Gateway VPC Attachments" \
    aws ec2 describe-transit-gateway-vpc-attachments --query 'TransitGatewayVpcAttachments[*].[TransitGatewayAttachmentId,VpcId,State,TransitGatewayId]' --output table

# ========================================
# Section 4: Infra-Dev-Network Account
# ========================================
echo "" | tee -a $OUTPUT_FILE
echo "###################################################" | tee -a $OUTPUT_FILE
echo "# INFRA-DEV-NETWORK ACCOUNT (940950790239)" | tee -a $OUTPUT_FILE
echo "###################################################" | tee -a $OUTPUT_FILE

run_command $INFRA_DEV_NET "4.1 Account Identity" \
    aws sts get-caller-identity

run_command $INFRA_DEV_NET "4.2 All VPCs" \
    aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,CidrBlock,Tags[?Key==`Name`].Value|[0],IsDefault]' --output table

# VPC DNS settings
echo "" | tee -a $OUTPUT_FILE
echo "4.3 VPC DNS Attributes for vpc-010c8e652fb1a5164" | tee -a $OUTPUT_FILE
aws ec2 describe-vpc-attribute --vpc-id vpc-010c8e652fb1a5164 --attribute enableDnsSupport --profile $INFRA_DEV_NET >> $OUTPUT_FILE 2>&1
aws ec2 describe-vpc-attribute --vpc-id vpc-010c8e652fb1a5164 --attribute enableDnsHostnames --profile $INFRA_DEV_NET >> $OUTPUT_FILE 2>&1

run_command $INFRA_DEV_NET "4.4 Resolver Rule Associations" \
    aws route53resolver list-resolver-rule-associations --query 'ResolverRuleAssociations[*].[ResolverRuleId,VPCId,Name]' --output table

run_command $INFRA_DEV_NET "4.5 RAM Resource Shares (Shared With Me)" \
    aws ram get-resource-shares --resource-owner OTHER-ACCOUNTS --query 'resourceShares[*].[name,resourceShareArn,status]' --output table

run_command $INFRA_DEV_NET "4.6 Private Hosted Zones" \
    aws route53 list-hosted-zones --query 'HostedZones[?Config.PrivateZone==`true`]'

run_command $INFRA_DEV_NET "4.7 Transit Gateway VPC Attachments" \
    aws ec2 describe-transit-gateway-vpc-attachments --query 'TransitGatewayVpcAttachments[*].[TransitGatewayAttachmentId,VpcId,State,TransitGatewayId]' --output table

# ========================================
# Section 5: Additional Discovery
# ========================================
echo "" | tee -a $OUTPUT_FILE
echo "###################################################" | tee -a $OUTPUT_FILE
echo "# ADDITIONAL DISCOVERY" | tee -a $OUTPUT_FILE
echo "###################################################" | tee -a $OUTPUT_FILE

# Get all subnets in Infra-Core VPC
run_command $INFRA_CORE "5.1 Subnets in Infra-Core VPC (vpc-08fcc16df5104273f)" \
    aws ec2 describe-subnets --filters "Name=vpc-id,Values=vpc-08fcc16df5104273f" --query 'Subnets[*].[SubnetId,CidrBlock,AvailabilityZone,Tags[?Key==`Name`].Value|[0]]' --output table

# Check DHCP Options Sets
run_command $INFRA_CORE "5.2 DHCP Options for Infra-Core VPC" \
    aws ec2 describe-vpcs --vpc-ids vpc-08fcc16df5104273f --query 'Vpcs[0].DhcpOptionsId' --output text

DHCP_OPTIONS=$(aws ec2 describe-vpcs --vpc-ids vpc-08fcc16df5104273f --profile $INFRA_CORE --query 'Vpcs[0].DhcpOptionsId' --output text 2>/dev/null)
if [ ! -z "$DHCP_OPTIONS" ] && [ "$DHCP_OPTIONS" != "None" ]; then
    echo "" | tee -a $OUTPUT_FILE
    echo "5.3 DHCP Options Configuration" | tee -a $OUTPUT_FILE
    aws ec2 describe-dhcp-options --dhcp-options-ids $DHCP_OPTIONS --profile $INFRA_CORE >> $OUTPUT_FILE 2>&1
fi

# ========================================
# Summary
# ========================================
echo "" | tee -a $OUTPUT_FILE
echo "==================================================" | tee -a $OUTPUT_FILE
echo "Discovery Complete!" | tee -a $OUTPUT_FILE
echo "Output saved to: $OUTPUT_FILE" | tee -a $OUTPUT_FILE
echo "==================================================" | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE
echo "Please share this file for DNS architecture analysis." | tee -a $OUTPUT_FILE

# Display file size and location
ls -lh $OUTPUT_FILE | tee -a $OUTPUT_FILE