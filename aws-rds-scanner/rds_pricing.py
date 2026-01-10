"""
AWS RDS On-Demand Instance Pricing (USD per hour)
Region: us-east-1 (N. Virginia)

Sources:
- https://aws.amazon.com/rds/pricing/
- https://aws.amazon.com/rds/mysql/pricing/
- https://aws.amazon.com/rds/postgresql/pricing/
- https://instances.vantage.sh/rds

Last updated: January 2025

Notes:
- Prices are for on-demand Single-AZ instances only
- Multi-AZ deployments are approximately 2x the Single-AZ price
- Reserved Instances and Savings Plans offer significant discounts
- Storage costs are separate (see STORAGE_PRICING)
- Prices may vary by region
- Aurora pricing is different and uses its own pricing model
"""

# Hours per month (average)
HOURS_PER_MONTH = 730

# RDS On-Demand Instance Pricing (USD per hour) - us-east-1
# Prices for common open-source engines (MySQL, PostgreSQL, MariaDB)
# Format: "instance_type": price_per_hour
RDS_PRICING = {
    # ==========================================================================
    # db.t3 Family - Burstable (Previous Gen)
    # ==========================================================================
    "db.t3.micro":      0.017,
    "db.t3.small":      0.034,
    "db.t3.medium":     0.068,
    "db.t3.large":      0.136,
    "db.t3.xlarge":     0.272,
    "db.t3.2xlarge":    0.544,

    # ==========================================================================
    # db.t4g Family - Burstable (Graviton2)
    # ==========================================================================
    "db.t4g.micro":     0.016,
    "db.t4g.small":     0.032,
    "db.t4g.medium":    0.065,
    "db.t4g.large":     0.129,
    "db.t4g.xlarge":    0.258,
    "db.t4g.2xlarge":   0.517,

    # ==========================================================================
    # db.m5 Family - General Purpose (Intel)
    # ==========================================================================
    "db.m5.large":      0.171,
    "db.m5.xlarge":     0.342,
    "db.m5.2xlarge":    0.684,
    "db.m5.4xlarge":    1.368,
    "db.m5.8xlarge":    2.736,
    "db.m5.12xlarge":   4.104,
    "db.m5.16xlarge":   5.472,
    "db.m5.24xlarge":   8.208,

    # ==========================================================================
    # db.m5d Family - General Purpose with NVMe (Intel)
    # ==========================================================================
    "db.m5d.large":     0.178,
    "db.m5d.xlarge":    0.356,
    "db.m5d.2xlarge":   0.712,
    "db.m5d.4xlarge":   1.424,
    "db.m5d.8xlarge":   2.848,
    "db.m5d.12xlarge":  4.272,
    "db.m5d.16xlarge":  5.696,
    "db.m5d.24xlarge":  8.544,

    # ==========================================================================
    # db.m6i Family - General Purpose (Intel 3rd Gen)
    # ==========================================================================
    "db.m6i.large":     0.171,
    "db.m6i.xlarge":    0.342,
    "db.m6i.2xlarge":   0.684,
    "db.m6i.4xlarge":   1.368,
    "db.m6i.8xlarge":   2.736,
    "db.m6i.12xlarge":  4.104,
    "db.m6i.16xlarge":  5.472,
    "db.m6i.24xlarge":  8.208,
    "db.m6i.32xlarge":  10.944,

    # ==========================================================================
    # db.m6g Family - General Purpose (Graviton2)
    # ==========================================================================
    "db.m6g.large":     0.154,
    "db.m6g.xlarge":    0.308,
    "db.m6g.2xlarge":   0.616,
    "db.m6g.4xlarge":   1.232,
    "db.m6g.8xlarge":   2.464,
    "db.m6g.12xlarge":  3.696,
    "db.m6g.16xlarge":  4.928,

    # ==========================================================================
    # db.m6gd Family - General Purpose with NVMe (Graviton2)
    # ==========================================================================
    "db.m6gd.large":    0.169,
    "db.m6gd.xlarge":   0.339,
    "db.m6gd.2xlarge":  0.678,
    "db.m6gd.4xlarge":  1.355,
    "db.m6gd.8xlarge":  2.710,
    "db.m6gd.12xlarge": 4.065,
    "db.m6gd.16xlarge": 5.420,

    # ==========================================================================
    # db.m7g Family - General Purpose (Graviton3)
    # ==========================================================================
    "db.m7g.large":     0.168,
    "db.m7g.xlarge":    0.336,
    "db.m7g.2xlarge":   0.672,
    "db.m7g.4xlarge":   1.344,
    "db.m7g.8xlarge":   2.688,
    "db.m7g.12xlarge":  4.032,
    "db.m7g.16xlarge":  5.376,

    # ==========================================================================
    # db.r5 Family - Memory Optimized (Intel)
    # ==========================================================================
    "db.r5.large":      0.250,
    "db.r5.xlarge":     0.500,
    "db.r5.2xlarge":    1.000,
    "db.r5.4xlarge":    2.000,
    "db.r5.8xlarge":    4.000,
    "db.r5.12xlarge":   6.000,
    "db.r5.16xlarge":   8.000,
    "db.r5.24xlarge":   12.000,

    # ==========================================================================
    # db.r5d Family - Memory Optimized with NVMe (Intel)
    # ==========================================================================
    "db.r5d.large":     0.260,
    "db.r5d.xlarge":    0.520,
    "db.r5d.2xlarge":   1.040,
    "db.r5d.4xlarge":   2.080,
    "db.r5d.8xlarge":   4.160,
    "db.r5d.12xlarge":  6.240,
    "db.r5d.16xlarge":  8.320,
    "db.r5d.24xlarge":  12.480,

    # ==========================================================================
    # db.r6i Family - Memory Optimized (Intel 3rd Gen)
    # ==========================================================================
    "db.r6i.large":     0.250,
    "db.r6i.xlarge":    0.500,
    "db.r6i.2xlarge":   1.000,
    "db.r6i.4xlarge":   2.000,
    "db.r6i.8xlarge":   4.000,
    "db.r6i.12xlarge":  6.000,
    "db.r6i.16xlarge":  8.000,
    "db.r6i.24xlarge":  12.000,
    "db.r6i.32xlarge":  16.000,

    # ==========================================================================
    # db.r6g Family - Memory Optimized (Graviton2)
    # ==========================================================================
    "db.r6g.large":     0.225,
    "db.r6g.xlarge":    0.450,
    "db.r6g.2xlarge":   0.900,
    "db.r6g.4xlarge":   1.800,
    "db.r6g.8xlarge":   3.600,
    "db.r6g.12xlarge":  5.400,
    "db.r6g.16xlarge":  7.200,

    # ==========================================================================
    # db.r6gd Family - Memory Optimized with NVMe (Graviton2)
    # ==========================================================================
    "db.r6gd.large":    0.248,
    "db.r6gd.xlarge":   0.495,
    "db.r6gd.2xlarge":  0.990,
    "db.r6gd.4xlarge":  1.980,
    "db.r6gd.8xlarge":  3.960,
    "db.r6gd.12xlarge": 5.940,
    "db.r6gd.16xlarge": 7.920,

    # ==========================================================================
    # db.r7g Family - Memory Optimized (Graviton3)
    # ==========================================================================
    "db.r7g.large":     0.247,
    "db.r7g.xlarge":    0.493,
    "db.r7g.2xlarge":   0.986,
    "db.r7g.4xlarge":   1.973,
    "db.r7g.8xlarge":   3.946,
    "db.r7g.12xlarge":  5.918,
    "db.r7g.16xlarge":  7.891,

    # ==========================================================================
    # db.x2g Family - Memory Optimized Extreme (Graviton2)
    # ==========================================================================
    "db.x2g.large":     0.417,
    "db.x2g.xlarge":    0.834,
    "db.x2g.2xlarge":   1.668,
    "db.x2g.4xlarge":   3.336,
    "db.x2g.8xlarge":   6.672,
    "db.x2g.12xlarge":  10.008,
    "db.x2g.16xlarge":  13.344,

    # ==========================================================================
    # Previous Generation (for reference)
    # ==========================================================================
    "db.t2.micro":      0.017,
    "db.t2.small":      0.034,
    "db.t2.medium":     0.068,
    "db.t2.large":      0.136,
    "db.t2.xlarge":     0.272,
    "db.t2.2xlarge":    0.544,

    "db.m4.large":      0.175,
    "db.m4.xlarge":     0.350,
    "db.m4.2xlarge":    0.700,
    "db.m4.4xlarge":    1.400,
    "db.m4.10xlarge":   3.500,
    "db.m4.16xlarge":   5.600,

    "db.r4.large":      0.250,
    "db.r4.xlarge":     0.500,
    "db.r4.2xlarge":    1.000,
    "db.r4.4xlarge":    2.000,
    "db.r4.8xlarge":    4.000,
    "db.r4.16xlarge":   8.000,
}

# Aurora-specific pricing (different from standard RDS)
# Aurora uses Aurora Capacity Units (ACUs) for Serverless v2
AURORA_PRICING = {
    # Aurora MySQL/PostgreSQL Standard instances
    "db.t3.small":      0.041,
    "db.t3.medium":     0.082,
    "db.t3.large":      0.164,

    "db.t4g.medium":    0.073,
    "db.t4g.large":     0.145,

    "db.r5.large":      0.290,
    "db.r5.xlarge":     0.580,
    "db.r5.2xlarge":    1.160,
    "db.r5.4xlarge":    2.320,
    "db.r5.8xlarge":    4.640,
    "db.r5.12xlarge":   6.960,
    "db.r5.16xlarge":   9.280,
    "db.r5.24xlarge":   13.920,

    "db.r6g.large":     0.260,
    "db.r6g.xlarge":    0.520,
    "db.r6g.2xlarge":   1.040,
    "db.r6g.4xlarge":   2.080,
    "db.r6g.8xlarge":   4.160,
    "db.r6g.12xlarge":  6.240,
    "db.r6g.16xlarge":  8.320,

    "db.r6i.large":     0.290,
    "db.r6i.xlarge":    0.580,
    "db.r6i.2xlarge":   1.160,
    "db.r6i.4xlarge":   2.320,
    "db.r6i.8xlarge":   4.640,
    "db.r6i.12xlarge":  6.960,
    "db.r6i.16xlarge":  9.280,
    "db.r6i.24xlarge":  13.920,
    "db.r6i.32xlarge":  18.560,

    "db.r7g.large":     0.286,
    "db.r7g.xlarge":    0.572,
    "db.r7g.2xlarge":   1.144,
    "db.r7g.4xlarge":   2.288,
    "db.r7g.8xlarge":   4.576,
    "db.r7g.12xlarge":  6.864,
    "db.r7g.16xlarge":  9.152,

    # Aurora Serverless v2: $0.12 per ACU-hour
    "serverless_v2_acu": 0.12,
}

# Storage pricing per GB-month
STORAGE_PRICING = {
    "gp2": 0.115,           # General Purpose SSD
    "gp3": 0.08,            # General Purpose SSD (gp3)
    "io1": 0.125,           # Provisioned IOPS SSD (+ $0.10 per IOPS)
    "io1_iops": 0.10,       # Per provisioned IOPS
    "magnetic": 0.10,       # Magnetic (standard)
    "aurora": 0.10,         # Aurora storage per GB-month
    "aurora_io": 0.20,      # Aurora I/O per million requests
}

# Backup storage (over provisioned storage)
BACKUP_PRICING = 0.095  # Per GB-month

# Aurora Serverless v2 pricing
SERVERLESS_V2_ACU_PRICE = 0.12  # Per ACU-hour (us-east-1)


def get_rds_hourly_cost(instance_class: str, engine: str, multi_az: bool = False) -> float:
    """Get hourly cost for an RDS instance.

    Args:
        instance_class: RDS instance class (e.g., 'db.t3.micro', 'db.m5.large')
        engine: Database engine (mysql, postgres, mariadb, aurora-mysql, aurora-postgresql, etc.)
        multi_az: Whether the instance is Multi-AZ deployment

    Returns:
        Hourly cost in USD, or 0.0 if instance class not found
    """
    instance_class = instance_class.lower()
    engine_lower = engine.lower() if engine else ""

    # Check if Aurora
    if "aurora" in engine_lower:
        price = AURORA_PRICING.get(instance_class, 0.0)
    else:
        price = RDS_PRICING.get(instance_class, 0.0)

    # Multi-AZ is approximately 2x the price
    if multi_az:
        price *= 2

    return price


def get_rds_monthly_cost(instance_class: str, engine: str, multi_az: bool = False) -> float:
    """Get estimated monthly cost for an RDS instance.

    Args:
        instance_class: RDS instance class (e.g., 'db.t3.micro', 'db.m5.large')
        engine: Database engine
        multi_az: Whether the instance is Multi-AZ deployment

    Returns:
        Monthly cost in USD (based on 730 hours), or 0.0 if instance class not found
    """
    hourly_cost = get_rds_hourly_cost(instance_class, engine, multi_az)
    return hourly_cost * HOURS_PER_MONTH


def get_storage_monthly_cost(storage_type: str, size_gb: int, iops: int = 0) -> float:
    """Get monthly storage cost.

    Args:
        storage_type: Storage type (gp2, gp3, io1, magnetic, aurora)
        size_gb: Storage size in GB
        iops: Provisioned IOPS (for io1)

    Returns:
        Monthly storage cost in USD
    """
    storage_type = storage_type.lower()
    base_cost = STORAGE_PRICING.get(storage_type, STORAGE_PRICING["gp2"]) * size_gb

    # Add IOPS cost for io1
    if storage_type == "io1" and iops > 0:
        base_cost += STORAGE_PRICING["io1_iops"] * iops

    return base_cost
