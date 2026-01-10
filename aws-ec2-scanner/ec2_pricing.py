"""
AWS EC2 On-Demand Instance Pricing (USD per hour)
Region: us-east-1 (N. Virginia)

Sources:
- https://aws.amazon.com/ec2/pricing/on-demand/
- https://instances.vantage.sh/

Last updated: January 2025

Notes:
- Prices are for on-demand instances only
- Reserved and Spot instances have different pricing
- Windows pricing includes OS license cost
- Prices may vary by region
"""

# Hours per month (average)
HOURS_PER_MONTH = 730

# EC2 On-Demand Instance Pricing (USD per hour) - us-east-1
# Format: "instance_type": {"linux": price, "windows": price}
EC2_PRICING = {
    # ==========================================================================
    # T2 Family - Burstable (Previous Generation)
    # ==========================================================================
    "t2.nano":       {"linux": 0.0058,  "windows": 0.0082},
    "t2.micro":      {"linux": 0.0116,  "windows": 0.0162},
    "t2.small":      {"linux": 0.023,   "windows": 0.032},
    "t2.medium":     {"linux": 0.0464,  "windows": 0.0568},
    "t2.large":      {"linux": 0.0928,  "windows": 0.1136},
    "t2.xlarge":     {"linux": 0.1856,  "windows": 0.2272},
    "t2.2xlarge":    {"linux": 0.3712,  "windows": 0.4544},

    # ==========================================================================
    # T3 Family - Burstable (Intel)
    # ==========================================================================
    "t3.nano":       {"linux": 0.0052,  "windows": 0.0074},
    "t3.micro":      {"linux": 0.0104,  "windows": 0.0148},
    "t3.small":      {"linux": 0.0208,  "windows": 0.0296},
    "t3.medium":     {"linux": 0.0416,  "windows": 0.0592},
    "t3.large":      {"linux": 0.0832,  "windows": 0.1184},
    "t3.xlarge":     {"linux": 0.1664,  "windows": 0.2368},
    "t3.2xlarge":    {"linux": 0.3328,  "windows": 0.4736},

    # ==========================================================================
    # T3a Family - Burstable (AMD)
    # ==========================================================================
    "t3a.nano":      {"linux": 0.0047,  "windows": 0.0067},
    "t3a.micro":     {"linux": 0.0094,  "windows": 0.0134},
    "t3a.small":     {"linux": 0.0188,  "windows": 0.0268},
    "t3a.medium":    {"linux": 0.0376,  "windows": 0.0536},
    "t3a.large":     {"linux": 0.0752,  "windows": 0.1072},
    "t3a.xlarge":    {"linux": 0.1504,  "windows": 0.2144},
    "t3a.2xlarge":   {"linux": 0.3008,  "windows": 0.4288},

    # ==========================================================================
    # M5 Family - General Purpose (Intel)
    # ==========================================================================
    "m5.large":      {"linux": 0.096,   "windows": 0.188},
    "m5.xlarge":     {"linux": 0.192,   "windows": 0.376},
    "m5.2xlarge":    {"linux": 0.384,   "windows": 0.752},
    "m5.4xlarge":    {"linux": 0.768,   "windows": 1.504},
    "m5.8xlarge":    {"linux": 1.536,   "windows": 3.008},
    "m5.12xlarge":   {"linux": 2.304,   "windows": 4.512},
    "m5.16xlarge":   {"linux": 3.072,   "windows": 6.016},
    "m5.24xlarge":   {"linux": 4.608,   "windows": 9.024},

    # ==========================================================================
    # M5a Family - General Purpose (AMD)
    # ==========================================================================
    "m5a.large":     {"linux": 0.086,   "windows": 0.178},
    "m5a.xlarge":    {"linux": 0.172,   "windows": 0.356},
    "m5a.2xlarge":   {"linux": 0.344,   "windows": 0.712},
    "m5a.4xlarge":   {"linux": 0.688,   "windows": 1.424},
    "m5a.8xlarge":   {"linux": 1.376,   "windows": 2.848},
    "m5a.12xlarge":  {"linux": 2.064,   "windows": 4.272},
    "m5a.16xlarge":  {"linux": 2.752,   "windows": 5.696},
    "m5a.24xlarge":  {"linux": 4.128,   "windows": 8.544},

    # ==========================================================================
    # M5n Family - General Purpose (Intel, Network Optimized)
    # ==========================================================================
    "m5n.large":     {"linux": 0.119,   "windows": 0.211},
    "m5n.xlarge":    {"linux": 0.238,   "windows": 0.422},
    "m5n.2xlarge":   {"linux": 0.476,   "windows": 0.844},
    "m5n.4xlarge":   {"linux": 0.952,   "windows": 1.688},
    "m5n.8xlarge":   {"linux": 1.904,   "windows": 3.376},
    "m5n.12xlarge":  {"linux": 2.856,   "windows": 5.064},
    "m5n.16xlarge":  {"linux": 3.808,   "windows": 6.752},
    "m5n.24xlarge":  {"linux": 5.712,   "windows": 10.128},

    # ==========================================================================
    # M6i Family - General Purpose (Intel 3rd Gen)
    # ==========================================================================
    "m6i.large":     {"linux": 0.096,   "windows": 0.188},
    "m6i.xlarge":    {"linux": 0.192,   "windows": 0.376},
    "m6i.2xlarge":   {"linux": 0.384,   "windows": 0.752},
    "m6i.4xlarge":   {"linux": 0.768,   "windows": 1.504},
    "m6i.8xlarge":   {"linux": 1.536,   "windows": 3.008},
    "m6i.12xlarge":  {"linux": 2.304,   "windows": 4.512},
    "m6i.16xlarge":  {"linux": 3.072,   "windows": 6.016},
    "m6i.24xlarge":  {"linux": 4.608,   "windows": 9.024},
    "m6i.32xlarge":  {"linux": 6.144,   "windows": 12.032},

    # ==========================================================================
    # M6a Family - General Purpose (AMD 3rd Gen)
    # ==========================================================================
    "m6a.large":     {"linux": 0.0864,  "windows": 0.1792},
    "m6a.xlarge":    {"linux": 0.1728,  "windows": 0.2016},
    "m6a.2xlarge":   {"linux": 0.3456,  "windows": 0.4464},
    "m6a.4xlarge":   {"linux": 0.6912,  "windows": 0.8064},
    "m6a.8xlarge":   {"linux": 1.3824,  "windows": 1.6128},
    "m6a.12xlarge":  {"linux": 2.0736,  "windows": 2.4192},
    "m6a.16xlarge":  {"linux": 2.7648,  "windows": 3.2256},
    "m6a.24xlarge":  {"linux": 4.1472,  "windows": 4.8384},
    "m6a.32xlarge":  {"linux": 5.5296,  "windows": 6.4512},
    "m6a.48xlarge":  {"linux": 8.2944,  "windows": 9.6768},

    # ==========================================================================
    # M7i Family - General Purpose (Intel 4th Gen)
    # ==========================================================================
    "m7i.large":     {"linux": 0.1008,  "windows": 0.1386},
    "m7i.xlarge":    {"linux": 0.2016,  "windows": 0.2772},
    "m7i.2xlarge":   {"linux": 0.4032,  "windows": 0.5544},
    "m7i.4xlarge":   {"linux": 0.8064,  "windows": 1.1088},
    "m7i.8xlarge":   {"linux": 1.6128,  "windows": 2.2176},
    "m7i.12xlarge":  {"linux": 2.4192,  "windows": 3.3264},
    "m7i.16xlarge":  {"linux": 3.2256,  "windows": 4.4352},
    "m7i.24xlarge":  {"linux": 4.8384,  "windows": 6.6528},
    "m7i.48xlarge":  {"linux": 9.6768,  "windows": 13.3056},

    # ==========================================================================
    # M7a Family - General Purpose (AMD 4th Gen)
    # ==========================================================================
    "m7a.medium":    {"linux": 0.05789, "windows": 0.1043},
    "m7a.large":     {"linux": 0.11578, "windows": 0.2086},
    "m7a.xlarge":    {"linux": 0.23155, "windows": 0.4171},
    "m7a.2xlarge":   {"linux": 0.4631,  "windows": 0.8343},
    "m7a.4xlarge":   {"linux": 0.9262,  "windows": 1.6686},
    "m7a.8xlarge":   {"linux": 1.8523,  "windows": 3.3371},
    "m7a.12xlarge":  {"linux": 2.7785,  "windows": 5.0057},
    "m7a.16xlarge":  {"linux": 3.7046,  "windows": 6.6742},
    "m7a.24xlarge":  {"linux": 5.557,   "windows": 10.0114},
    "m7a.48xlarge":  {"linux": 11.1139, "windows": 20.0227},

    # ==========================================================================
    # C5 Family - Compute Optimized (Intel)
    # ==========================================================================
    "c5.large":      {"linux": 0.085,   "windows": 0.177},
    "c5.xlarge":     {"linux": 0.17,    "windows": 0.354},
    "c5.2xlarge":    {"linux": 0.34,    "windows": 0.708},
    "c5.4xlarge":    {"linux": 0.68,    "windows": 1.416},
    "c5.9xlarge":    {"linux": 1.53,    "windows": 3.186},
    "c5.12xlarge":   {"linux": 2.04,    "windows": 4.248},
    "c5.18xlarge":   {"linux": 3.06,    "windows": 6.372},
    "c5.24xlarge":   {"linux": 4.08,    "windows": 8.496},

    # ==========================================================================
    # C5a Family - Compute Optimized (AMD)
    # ==========================================================================
    "c5a.large":     {"linux": 0.077,   "windows": 0.169},
    "c5a.xlarge":    {"linux": 0.154,   "windows": 0.338},
    "c5a.2xlarge":   {"linux": 0.308,   "windows": 0.676},
    "c5a.4xlarge":   {"linux": 0.616,   "windows": 1.352},
    "c5a.8xlarge":   {"linux": 1.232,   "windows": 2.704},
    "c5a.12xlarge":  {"linux": 1.848,   "windows": 4.056},
    "c5a.16xlarge":  {"linux": 2.464,   "windows": 5.408},
    "c5a.24xlarge":  {"linux": 3.696,   "windows": 8.112},

    # ==========================================================================
    # C5n Family - Compute Optimized (Intel, Network Optimized)
    # ==========================================================================
    "c5n.large":     {"linux": 0.108,   "windows": 0.2},
    "c5n.xlarge":    {"linux": 0.216,   "windows": 0.4},
    "c5n.2xlarge":   {"linux": 0.432,   "windows": 0.8},
    "c5n.4xlarge":   {"linux": 0.864,   "windows": 1.6},
    "c5n.9xlarge":   {"linux": 1.944,   "windows": 3.6},
    "c5n.18xlarge":  {"linux": 3.888,   "windows": 7.2},

    # ==========================================================================
    # C6i Family - Compute Optimized (Intel 3rd Gen)
    # ==========================================================================
    "c6i.large":     {"linux": 0.085,   "windows": 0.177},
    "c6i.xlarge":    {"linux": 0.17,    "windows": 0.354},
    "c6i.2xlarge":   {"linux": 0.34,    "windows": 0.708},
    "c6i.4xlarge":   {"linux": 0.68,    "windows": 1.416},
    "c6i.8xlarge":   {"linux": 1.36,    "windows": 2.832},
    "c6i.12xlarge":  {"linux": 2.04,    "windows": 4.248},
    "c6i.16xlarge":  {"linux": 2.72,    "windows": 5.664},
    "c6i.24xlarge":  {"linux": 4.08,    "windows": 8.496},
    "c6i.32xlarge":  {"linux": 5.44,    "windows": 11.328},

    # ==========================================================================
    # C6a Family - Compute Optimized (AMD 3rd Gen)
    # ==========================================================================
    "c6a.large":     {"linux": 0.0765,  "windows": 0.1693},
    "c6a.xlarge":    {"linux": 0.153,   "windows": 0.1998},
    "c6a.2xlarge":   {"linux": 0.306,   "windows": 0.3888},
    "c6a.4xlarge":   {"linux": 0.612,   "windows": 0.7776},
    "c6a.8xlarge":   {"linux": 1.224,   "windows": 1.5552},
    "c6a.12xlarge":  {"linux": 1.836,   "windows": 2.3328},
    "c6a.16xlarge":  {"linux": 2.448,   "windows": 3.1104},
    "c6a.24xlarge":  {"linux": 3.672,   "windows": 4.6656},
    "c6a.32xlarge":  {"linux": 4.896,   "windows": 6.2208},
    "c6a.48xlarge":  {"linux": 7.344,   "windows": 9.3312},

    # ==========================================================================
    # C7i Family - Compute Optimized (Intel 4th Gen)
    # ==========================================================================
    "c7i.large":     {"linux": 0.08925, "windows": 0.18125},
    "c7i.xlarge":    {"linux": 0.1785,  "windows": 0.3625},
    "c7i.2xlarge":   {"linux": 0.357,   "windows": 0.725},
    "c7i.4xlarge":   {"linux": 0.714,   "windows": 1.45},
    "c7i.8xlarge":   {"linux": 1.428,   "windows": 2.9},
    "c7i.12xlarge":  {"linux": 2.142,   "windows": 4.35},
    "c7i.16xlarge":  {"linux": 2.856,   "windows": 5.8},
    "c7i.24xlarge":  {"linux": 4.284,   "windows": 8.7},
    "c7i.48xlarge":  {"linux": 8.568,   "windows": 17.4},

    # ==========================================================================
    # C7a Family - Compute Optimized (AMD 4th Gen)
    # ==========================================================================
    "c7a.medium":    {"linux": 0.05208, "windows": 0.09868},
    "c7a.large":     {"linux": 0.10416, "windows": 0.19736},
    "c7a.xlarge":    {"linux": 0.20831, "windows": 0.39471},
    "c7a.2xlarge":   {"linux": 0.41663, "windows": 0.78943},
    "c7a.4xlarge":   {"linux": 0.83325, "windows": 1.57885},
    "c7a.8xlarge":   {"linux": 1.6665,  "windows": 3.1577},
    "c7a.12xlarge":  {"linux": 2.49975, "windows": 4.73655},
    "c7a.16xlarge":  {"linux": 3.333,   "windows": 6.3154},
    "c7a.24xlarge":  {"linux": 4.9995,  "windows": 9.4731},
    "c7a.48xlarge":  {"linux": 9.999,   "windows": 18.9462},

    # ==========================================================================
    # R5 Family - Memory Optimized (Intel)
    # ==========================================================================
    "r5.large":      {"linux": 0.126,   "windows": 0.218},
    "r5.xlarge":     {"linux": 0.252,   "windows": 0.436},
    "r5.2xlarge":    {"linux": 0.504,   "windows": 0.872},
    "r5.4xlarge":    {"linux": 1.008,   "windows": 1.744},
    "r5.8xlarge":    {"linux": 2.016,   "windows": 3.488},
    "r5.12xlarge":   {"linux": 3.024,   "windows": 5.232},
    "r5.16xlarge":   {"linux": 4.032,   "windows": 6.976},
    "r5.24xlarge":   {"linux": 6.048,   "windows": 10.464},

    # ==========================================================================
    # R5a Family - Memory Optimized (AMD)
    # ==========================================================================
    "r5a.large":     {"linux": 0.113,   "windows": 0.205},
    "r5a.xlarge":    {"linux": 0.226,   "windows": 0.41},
    "r5a.2xlarge":   {"linux": 0.452,   "windows": 0.82},
    "r5a.4xlarge":   {"linux": 0.904,   "windows": 1.64},
    "r5a.8xlarge":   {"linux": 1.808,   "windows": 3.28},
    "r5a.12xlarge":  {"linux": 2.712,   "windows": 4.92},
    "r5a.16xlarge":  {"linux": 3.616,   "windows": 6.56},
    "r5a.24xlarge":  {"linux": 5.424,   "windows": 9.84},

    # ==========================================================================
    # R5n Family - Memory Optimized (Intel, Network Optimized)
    # ==========================================================================
    "r5n.large":     {"linux": 0.149,   "windows": 0.241},
    "r5n.xlarge":    {"linux": 0.298,   "windows": 0.482},
    "r5n.2xlarge":   {"linux": 0.596,   "windows": 0.964},
    "r5n.4xlarge":   {"linux": 1.192,   "windows": 1.928},
    "r5n.8xlarge":   {"linux": 2.384,   "windows": 3.856},
    "r5n.12xlarge":  {"linux": 3.576,   "windows": 5.784},
    "r5n.16xlarge":  {"linux": 4.768,   "windows": 7.712},
    "r5n.24xlarge":  {"linux": 7.152,   "windows": 11.568},

    # ==========================================================================
    # R6i Family - Memory Optimized (Intel 3rd Gen)
    # ==========================================================================
    "r6i.large":     {"linux": 0.126,   "windows": 0.218},
    "r6i.xlarge":    {"linux": 0.252,   "windows": 0.436},
    "r6i.2xlarge":   {"linux": 0.504,   "windows": 0.872},
    "r6i.4xlarge":   {"linux": 1.008,   "windows": 1.744},
    "r6i.8xlarge":   {"linux": 2.016,   "windows": 3.488},
    "r6i.12xlarge":  {"linux": 3.024,   "windows": 5.232},
    "r6i.16xlarge":  {"linux": 4.032,   "windows": 6.976},
    "r6i.24xlarge":  {"linux": 6.048,   "windows": 10.464},
    "r6i.32xlarge":  {"linux": 8.064,   "windows": 13.952},

    # ==========================================================================
    # R6a Family - Memory Optimized (AMD 3rd Gen)
    # ==========================================================================
    "r6a.large":     {"linux": 0.1134,  "windows": 0.2288},
    "r6a.xlarge":    {"linux": 0.2268,  "windows": 0.3299},
    "r6a.2xlarge":   {"linux": 0.4536,  "windows": 0.9152},
    "r6a.4xlarge":   {"linux": 0.9072,  "windows": 1.2194},
    "r6a.8xlarge":   {"linux": 1.8144,  "windows": 2.4387},
    "r6a.12xlarge":  {"linux": 2.7216,  "windows": 3.6581},
    "r6a.16xlarge":  {"linux": 3.6288,  "windows": 4.8774},
    "r6a.24xlarge":  {"linux": 5.4432,  "windows": 7.3162},
    "r6a.32xlarge":  {"linux": 7.2576,  "windows": 9.7549},
    "r6a.48xlarge":  {"linux": 10.8864, "windows": 14.6323},

    # ==========================================================================
    # R7i Family - Memory Optimized (Intel 4th Gen)
    # ==========================================================================
    "r7i.large":     {"linux": 0.13230, "windows": 0.22430},
    "r7i.xlarge":    {"linux": 0.2646,  "windows": 0.4486},
    "r7i.2xlarge":   {"linux": 0.5292,  "windows": 0.8972},
    "r7i.4xlarge":   {"linux": 1.0584,  "windows": 1.7944},
    "r7i.8xlarge":   {"linux": 2.1168,  "windows": 3.5888},
    "r7i.12xlarge":  {"linux": 3.1752,  "windows": 5.3832},
    "r7i.16xlarge":  {"linux": 4.2336,  "windows": 7.1776},
    "r7i.24xlarge":  {"linux": 6.3504,  "windows": 10.7664},
    "r7i.48xlarge":  {"linux": 12.7008, "windows": 21.5328},

    # ==========================================================================
    # R7a Family - Memory Optimized (AMD 4th Gen)
    # ==========================================================================
    "r7a.medium":    {"linux": 0.07561, "windows": 0.12221},
    "r7a.large":     {"linux": 0.15122, "windows": 0.24442},
    "r7a.xlarge":    {"linux": 0.30245, "windows": 0.48885},
    "r7a.2xlarge":   {"linux": 0.6049,  "windows": 0.9777},
    "r7a.4xlarge":   {"linux": 1.2098,  "windows": 1.9554},
    "r7a.8xlarge":   {"linux": 2.4195,  "windows": 3.9107},
    "r7a.12xlarge":  {"linux": 3.6293,  "windows": 5.8661},
    "r7a.16xlarge":  {"linux": 4.839,   "windows": 7.8214},
    "r7a.24xlarge":  {"linux": 7.2586,  "windows": 11.7322},
    "r7a.48xlarge":  {"linux": 14.5171, "windows": 23.4643},

    # ==========================================================================
    # I3 Family - Storage Optimized (Intel)
    # ==========================================================================
    "i3.large":      {"linux": 0.156,   "windows": 0.248},
    "i3.xlarge":     {"linux": 0.312,   "windows": 0.496},
    "i3.2xlarge":    {"linux": 0.624,   "windows": 0.992},
    "i3.4xlarge":    {"linux": 1.248,   "windows": 1.984},
    "i3.8xlarge":    {"linux": 2.496,   "windows": 3.968},
    "i3.16xlarge":   {"linux": 4.992,   "windows": 7.936},

    # ==========================================================================
    # I3en Family - Storage Optimized (Intel, NVMe)
    # ==========================================================================
    "i3en.large":    {"linux": 0.226,   "windows": 0.318},
    "i3en.xlarge":   {"linux": 0.452,   "windows": 0.636},
    "i3en.2xlarge":  {"linux": 0.904,   "windows": 1.272},
    "i3en.3xlarge":  {"linux": 1.356,   "windows": 1.908},
    "i3en.6xlarge":  {"linux": 2.712,   "windows": 3.816},
    "i3en.12xlarge": {"linux": 5.424,   "windows": 7.632},
    "i3en.24xlarge": {"linux": 10.848,  "windows": 15.264},

    # ==========================================================================
    # D2 Family - Dense Storage (Previous Gen)
    # ==========================================================================
    "d2.xlarge":     {"linux": 0.69,    "windows": 0.782},
    "d2.2xlarge":    {"linux": 1.38,    "windows": 1.564},
    "d2.4xlarge":    {"linux": 2.76,    "windows": 3.128},
    "d2.8xlarge":    {"linux": 5.52,    "windows": 6.256},

    # ==========================================================================
    # D3 Family - Dense Storage
    # ==========================================================================
    "d3.xlarge":     {"linux": 0.499,   "windows": 0.591},
    "d3.2xlarge":    {"linux": 0.999,   "windows": 1.183},
    "d3.4xlarge":    {"linux": 1.998,   "windows": 2.366},
    "d3.8xlarge":    {"linux": 3.996,   "windows": 4.732},

    # ==========================================================================
    # G4dn Family - GPU (NVIDIA T4)
    # ==========================================================================
    "g4dn.xlarge":   {"linux": 0.526,   "windows": 0.71},
    "g4dn.2xlarge":  {"linux": 0.752,   "windows": 1.12},
    "g4dn.4xlarge":  {"linux": 1.204,   "windows": 1.94},
    "g4dn.8xlarge":  {"linux": 2.176,   "windows": 3.648},
    "g4dn.12xlarge": {"linux": 3.912,   "windows": 6.12},
    "g4dn.16xlarge": {"linux": 4.352,   "windows": 7.296},

    # ==========================================================================
    # G5 Family - GPU (NVIDIA A10G)
    # ==========================================================================
    "g5.xlarge":     {"linux": 1.006,   "windows": 1.374},
    "g5.2xlarge":    {"linux": 1.212,   "windows": 1.764},
    "g5.4xlarge":    {"linux": 1.624,   "windows": 2.544},
    "g5.8xlarge":    {"linux": 2.448,   "windows": 4.104},
    "g5.12xlarge":   {"linux": 5.672,   "windows": 8.432},
    "g5.16xlarge":   {"linux": 4.096,   "windows": 7.224},
    "g5.24xlarge":   {"linux": 8.144,   "windows": 12.664},
    "g5.48xlarge":   {"linux": 16.288,  "windows": 25.328},

    # ==========================================================================
    # P3 Family - GPU (NVIDIA V100)
    # ==========================================================================
    "p3.2xlarge":    {"linux": 3.06,    "windows": 3.978},
    "p3.8xlarge":    {"linux": 12.24,   "windows": 15.912},
    "p3.16xlarge":   {"linux": 24.48,   "windows": 31.824},

    # ==========================================================================
    # P4d Family - GPU (NVIDIA A100)
    # ==========================================================================
    "p4d.24xlarge":  {"linux": 32.7726, "windows": 37.3086},

    # ==========================================================================
    # Inf1 Family - Inference (AWS Inferentia)
    # ==========================================================================
    "inf1.xlarge":   {"linux": 0.368,   "windows": 0.552},
    "inf1.2xlarge":  {"linux": 0.584,   "windows": 0.952},
    "inf1.6xlarge":  {"linux": 1.904,   "windows": 3.008},
    "inf1.24xlarge": {"linux": 7.615,   "windows": 12.031},

    # ==========================================================================
    # Inf2 Family - Inference (AWS Inferentia2)
    # ==========================================================================
    "inf2.xlarge":   {"linux": 0.7582,  "windows": 0.9422},
    "inf2.8xlarge":  {"linux": 1.9678,  "windows": 2.8878},
    "inf2.24xlarge": {"linux": 6.4907,  "windows": 9.2507},
    "inf2.48xlarge": {"linux": 12.9813, "windows": 18.5013},

    # ==========================================================================
    # X1 Family - Memory Optimized (High Memory)
    # ==========================================================================
    "x1.16xlarge":   {"linux": 6.669,   "windows": 9.485},
    "x1.32xlarge":   {"linux": 13.338,  "windows": 18.97},

    # ==========================================================================
    # X1e Family - Memory Optimized (Extreme Memory)
    # ==========================================================================
    "x1e.xlarge":    {"linux": 0.834,   "windows": 1.018},
    "x1e.2xlarge":   {"linux": 1.668,   "windows": 2.036},
    "x1e.4xlarge":   {"linux": 3.336,   "windows": 4.072},
    "x1e.8xlarge":   {"linux": 6.672,   "windows": 8.144},
    "x1e.16xlarge":  {"linux": 13.344,  "windows": 16.288},
    "x1e.32xlarge":  {"linux": 26.688,  "windows": 32.576},

    # ==========================================================================
    # X2idn Family - Memory Optimized (Intel, NVMe)
    # ==========================================================================
    "x2idn.16xlarge": {"linux": 6.669,  "windows": 9.613},
    "x2idn.24xlarge": {"linux": 10.0035, "windows": 14.4195},
    "x2idn.32xlarge": {"linux": 13.338, "windows": 19.226},

    # ==========================================================================
    # X2iedn Family - Memory Optimized (Intel, NVMe, Extended)
    # ==========================================================================
    "x2iedn.xlarge":   {"linux": 0.83375, "windows": 1.01775},
    "x2iedn.2xlarge":  {"linux": 1.6675,  "windows": 2.0355},
    "x2iedn.4xlarge":  {"linux": 3.335,   "windows": 4.071},
    "x2iedn.8xlarge":  {"linux": 6.67,    "windows": 8.142},
    "x2iedn.16xlarge": {"linux": 13.34,   "windows": 16.284},
    "x2iedn.24xlarge": {"linux": 20.01,   "windows": 24.426},
    "x2iedn.32xlarge": {"linux": 26.68,   "windows": 32.568},

    # ==========================================================================
    # Z1d Family - High Frequency
    # ==========================================================================
    "z1d.large":     {"linux": 0.186,   "windows": 0.278},
    "z1d.xlarge":    {"linux": 0.372,   "windows": 0.556},
    "z1d.2xlarge":   {"linux": 0.744,   "windows": 1.112},
    "z1d.3xlarge":   {"linux": 1.116,   "windows": 1.668},
    "z1d.6xlarge":   {"linux": 2.232,   "windows": 3.336},
    "z1d.12xlarge":  {"linux": 4.464,   "windows": 6.672},
}


def get_instance_hourly_cost(instance_type: str, platform: str) -> float:
    """Get hourly cost for an EC2 instance type and platform.

    Args:
        instance_type: EC2 instance type (e.g., 'm5.large', 'c6a.2xlarge')
        platform: Platform string (containing 'Windows' or assuming Linux)

    Returns:
        Hourly cost in USD, or 0.0 if instance type not found
    """
    instance_type = instance_type.lower()
    platform_key = "windows" if "windows" in platform.lower() else "linux"

    if instance_type in EC2_PRICING:
        return EC2_PRICING[instance_type].get(platform_key, 0.0)

    # For unknown instance types, return 0 (user can check AWS pricing)
    return 0.0


def get_instance_monthly_cost(instance_type: str, platform: str) -> float:
    """Get estimated monthly cost for an EC2 instance type and platform.

    Args:
        instance_type: EC2 instance type (e.g., 'm5.large', 'c6a.2xlarge')
        platform: Platform string (containing 'Windows' or assuming Linux)

    Returns:
        Monthly cost in USD (based on 730 hours), or 0.0 if instance type not found
    """
    hourly_cost = get_instance_hourly_cost(instance_type, platform)
    return hourly_cost * HOURS_PER_MONTH
