# API Load Tester

A comprehensive API load testing and benchmarking tool that measures detailed timing metrics for HTTP/HTTPS endpoints.

## Features

- **Detailed Timing Breakdown**: Measures DNS resolution, TCP connection, TLS handshake, TTFB, and total request time
- **Virtual Users (Concurrency)**: Simulate multiple concurrent users with `-c` option
- **Load Patterns**: Support for constant, ramp-up, step, spike, and soak test patterns
- **Keep-Alive Connections**: Reuse TCP/TLS connections for realistic performance (enabled by default)
- **Target QPS Rate Limiting**: Control throughput with `-q` option to avoid overwhelming servers
- **Response Validation**: Validate status codes and response body content
- **QPS Metrics**: Real-time and summary Queries Per Second (throughput) reporting
- **Flexible Test Options**: Run tests by request count or duration
- **Visual Reports**: ASCII graphs including histograms, timelines, and stacked bar charts
- **Multiple HTTP Methods**: Support for GET, POST, PUT, PATCH, DELETE, HEAD
- **Custom Headers**: Add authentication and custom headers via CLI or environment variables
- **JSON Export**: Export detailed results for further analysis
- **HTML Reports**: Interactive Locust-style HTML reports with Chart.js visualizations
- **Color-Coded Output**: Easy-to-read terminal output with status highlighting

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Setup

1. Navigate to the script directory:
   ```bash
   cd api-load-tester
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. (Optional) Configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys if needed
   ```

## Usage

### Basic Usage

Test an endpoint with 10 requests (default):
```bash
python api_load_test.py https://api.example.com/health
```

### Specify Number of Requests

Run 100 requests:
```bash
python api_load_test.py https://api.example.com/users -n 100
```

### Run for Duration

Run test for 60 seconds:
```bash
python api_load_test.py https://api.example.com/data -d 60
```

### Verbose Output

Show detailed timing for each request:
```bash
python api_load_test.py https://api.example.com/health -n 20 -v
```

### Different HTTP Methods

POST request with JSON body:
```bash
python api_load_test.py https://api.example.com/users -m POST --data '{"name":"test"}'
```

### Custom Headers

Add authentication headers:
```bash
python api_load_test.py https://api.example.com/secure \
  -H "Authorization: Bearer your-token" \
  -H "X-API-Key: your-key"
```

### Add Delay Between Requests

Add 100ms delay between requests:
```bash
python api_load_test.py https://api.example.com/rate-limited -n 50 --delay 100
```

### Export Results

Save results to JSON file:
```bash
python api_load_test.py https://api.example.com/health -n 100 -o results.json
```

### HTML Report (Locust-style)

Generate an interactive HTML report with charts:
```bash
python api_load_test.py https://api.example.com/health -n 100 --html report.html
```

The HTML report includes:
- Summary statistics cards
- Response time over time chart
- Requests per second chart
- Response time distribution histogram
- Timing breakdown doughnut chart
- Virtual users over time chart (when using load patterns)
- Detailed timing statistics table
- Error summary (if any failures)

### Minimal Output

Disable graphical output:
```bash
python api_load_test.py https://api.example.com/health --no-graph
```

### Virtual Users (Concurrency)

Simulate 10 concurrent users:
```bash
python api_load_test.py https://api.example.com/stress -n 100 -c 10
```

Run 5 virtual users for 30 seconds:
```bash
python api_load_test.py https://api.example.com/load -d 30 -c 5
```

### Target QPS (Rate Limiting)

Limit requests to 50 per second:
```bash
python api_load_test.py https://api.example.com/api -n 100 -q 50
```

Run at 10 QPS with 5 virtual users:
```bash
python api_load_test.py https://api.example.com/api -d 60 -c 5 -q 10
```

### Keep-Alive Connections

Keep-alive is enabled by default for better performance. To disable:
```bash
python api_load_test.py https://api.example.com/api -n 100 --no-keepalive
```

### Load Testing Patterns

The tool supports five load patterns to simulate different real-world traffic scenarios. Use the `--pattern` option to select a pattern (requires `-d` duration mode for dynamic patterns).

#### Constant Pattern (default)
All virtual users start immediately and maintain steady load throughout the test.

**Ideal for**: Baseline performance testing, steady-state validation, comparing results across tests.

```bash
# 10 users constant load for 60 seconds
python api_load_test.py https://api.example.com/api -d 60 -c 10 --pattern constant
```

#### Ramp-Up Pattern
Gradually increases users from 1 to the maximum over a specified duration. Useful for observing how performance degrades as load increases.

**Ideal for**: Finding breaking points, capacity planning, identifying scalability issues.

```bash
# Ramp from 1 to 20 users over 30 seconds, then hold for remaining time
python api_load_test.py https://api.example.com/api -d 120 -c 20 --pattern ramp-up --ramp-duration 30
```

Options:
- `--ramp-duration`: Time in seconds to reach max users (default: 50% of total duration)

#### Step Pattern
Increases users in discrete steps, holding each level before adding more. Creates a staircase load profile.

**Ideal for**: Identifying performance thresholds at specific user counts, capacity testing with clear breakpoints.

```bash
# Add 2 users every 15 seconds up to 10 users
python api_load_test.py https://api.example.com/api -d 120 -c 10 --pattern step --step-users 2 --step-duration 15
```

Options:
- `--step-users`: Number of users to add per step (default: 1)
- `--step-duration`: Duration of each step in seconds (default: 10)

#### Spike Pattern
Maintains baseline load, then suddenly spikes to peak load, then returns to baseline. Simulates traffic surges.

**Ideal for**: Testing auto-scaling, flash sale scenarios, sudden traffic bursts, recovery behavior.

```bash
# 5 users baseline, spike to 50 users after 20 seconds for 10 seconds
python api_load_test.py https://api.example.com/api -d 60 -c 5 --pattern spike \
  --spike-users 50 --spike-delay 20 --spike-duration 10
```

Options:
- `--spike-users`: Peak number of users during spike (default: 2x normal)
- `--spike-delay`: Delay before spike starts in seconds (default: 30% of duration)
- `--spike-duration`: How long the spike lasts in seconds (default: 10)

#### Soak Pattern
Same as constant but semantically indicates a long-duration endurance test. Use for extended periods to detect memory leaks, connection exhaustion, or gradual degradation.

**Ideal for**: Memory leak detection, connection pool exhaustion, long-term stability testing.

```bash
# Soak test with 10 users for 30 minutes
python api_load_test.py https://api.example.com/api -d 1800 -c 10 --pattern soak
```

### Load Pattern Comparison

| Pattern | Use Case | User Growth |
|---------|----------|-------------|
| **constant** | Baseline testing | Flat line |
| **ramp-up** | Find breaking points | Gradual increase |
| **step** | Threshold identification | Staircase |
| **spike** | Burst traffic testing | Baseline → Peak → Baseline |
| **soak** | Endurance testing | Flat line (long duration) |

### Response Validation

Validate expected status code:
```bash
python api_load_test.py https://api.example.com/health --expect-status 200
```

Validate response body contains specific text:
```bash
python api_load_test.py https://api.example.com/api --expect-body '"status":"ok"'
```

Combine both validations:
```bash
python api_load_test.py https://api.example.com/api \
  --expect-status 200 \
  --expect-body '"success":true'
```

Note: The script exits with code 1 if any validation errors occur (useful for CI/CD).

### Combined Options

Full example with multiple options:
```bash
python api_load_test.py https://api.example.com/data \
  -n 100 \
  -c 5 \
  -q 20 \
  -m POST \
  --data '{"key":"value"}' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer token123" \
  --expect-status 200 \
  -v \
  -o results.json
```

## Output Format

### Console Output

The report includes:
- **Summary**: Total requests, success/failure counts, success rate
- **Throughput**: Virtual users, duration, QPS (queries per second)
- **Status Codes**: Distribution of HTTP status codes
- **Timing Metrics**: Min, avg, median, P90, P95, max for each timing component
- **Visualizations**:
  - Timing breakdown bar chart
  - Response time timeline
  - Response time distribution histogram

### JSON Export

```json
{
  "timestamp": "2024-01-15T10:30:00.123456",
  "summary": {
    "total_requests": 100,
    "successful": 98,
    "failed": 2,
    "success_rate": 98.0,
    "duration_seconds": 12.5,
    "virtual_users": 5,
    "target_qps": 20,
    "qps": 8.0,
    "successful_qps": 7.84,
    "connections_reused": 95,
    "validation_errors": 0,
    "status_codes": {"200": 98, "-1": 2},
    "metrics": {
      "dns_ms": {"min": 1.2, "avg": 2.5, "median": 2.3, "p90": 3.8, "p95": 4.2, "max": 8.1},
      "tcp_ms": {"min": 5.1, "avg": 8.2, "median": 7.5, "p90": 12.3, "p95": 15.1, "max": 25.0},
      "tls_ms": {"min": 15.2, "avg": 22.5, "median": 21.0, "p90": 30.5, "p95": 35.2, "max": 50.1},
      "ttfb_ms": {"min": 10.5, "avg": 25.3, "median": 22.1, "p90": 40.2, "p95": 48.5, "max": 85.0},
      "total_ms": {"min": 35.5, "avg": 58.5, "median": 53.2, "p90": 85.3, "p95": 102.1, "max": 168.2}
    }
  },
  "requests": [
    {
      "url": "https://api.example.com/health",
      "timestamp": "2024-01-15T10:30:00.123456",
      "dns_ms": 2.3,
      "tcp_ms": 7.5,
      "tls_ms": 21.0,
      "ttfb_ms": 22.1,
      "total_ms": 53.2,
      "status_code": 200,
      "response_size": 125,
      "error": null,
      "resolved_ip": "93.184.216.34",
      "connection_reused": true,
      "validation_error": null
    }
  ]
}
```

## Metrics Glossary

### Timing Metrics

| Metric | Description |
|--------|-------------|
| **DNS** | Time to resolve hostname to IP address |
| **TCP** | Time to establish TCP connection |
| **TLS** | Time to complete TLS/SSL handshake (HTTPS only) |
| **TTFB** | Time to First Byte - server processing time |
| **Total** | Complete request time from start to finish |

### Throughput Metrics

| Metric | Description |
|--------|-------------|
| **Virtual Users (VUs)** | Number of concurrent simulated users making requests in parallel |
| **QPS** | Queries Per Second - total requests completed per second (throughput) |
| **Successful QPS** | QPS counting only successful (non-error) requests |
| **Target QPS** | User-specified rate limit for request throughput |
| **Connections Reused** | Number of requests that reused existing TCP/TLS connections (keep-alive) |
| **Validation Errors** | Number of requests that failed response validation checks |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `API_KEY` | Automatically added as `X-API-Key` header |
| `BEARER_TOKEN` | Automatically added as `Authorization: Bearer` header |
| `CUSTOM_HEADERS` | JSON object of additional headers |

## Troubleshooting

### SSL Certificate Errors
If you encounter SSL errors, ensure the target server has a valid certificate. For self-signed certs, you may need to modify the script to disable verification (not recommended for production).

### Connection Timeouts
The default timeout is 30 seconds. For slow endpoints, you may need to modify the `timeout` parameter in the script.

### Rate Limiting
If the target API has rate limiting, use the `--delay` option to add delays between requests.

## Security Notes

- API keys and tokens loaded from `.env` are not logged or exported
- The `.env` file is excluded from version control via `.gitignore`
- Be cautious when testing production APIs - ensure you have permission
- Consider the load impact on target servers
