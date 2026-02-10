# xc-count-lb-objects-by-label

This script collects detailed statistics for every HTTP and TCP load balancer in an F5 Distributed Cloud (XC) tenant and exports the results to a CSV file.

It enumerates all namespaces, inspects each load balancer, searches for a specific billing label, and calculates total billable object and HTTP request counts per load balancer over a specified time window.

## Features

For each load balancer in every namespace, the script outputs:

- Namespace  
- Load balancer name  
- Label value (default: `application`, customizable)  
- Load balancer type (`http` or `tcp`)  
- API Discovery enabled (HTTP only)  
- WAF enabled (HTTP only)  
- Malicious user detection enabled (HTTP only)  
- Malicious user protection enabled (HTTP only)  
- Total HTTP requests over selected time range (HTTP only)  
- Any issues encountered during data collection  

This provides a full per-load-balancer usage view across your tenant.

## Requirements

- Python 3.8+
- requests library

Install dependencies:

```bash
pip install requests
````

## Usage

```bash
python xc_namespace_lb_stats_updated.py \
  --base_url https://<tenant>.console.ves.volterra.io \
  --api_token <YOUR_API_TOKEN> \
  --output output.csv
```

## Required Arguments

* `--base_url`
  Base URL of your XC tenant

* `--api_token`
  XC API token

## Optional Arguments

* `--output` (default: `xc_usage_stats.csv`)
  Output CSV filename

* `--days` (default: `30`)
  Number of days of HTTP request data to calculate

* `--label` (default: `application`)
  Label key used for reporting (for example: application, team, owner)

* `--insecure`
  Disable SSL verification

* `--no-progress`
  Disable progress output during execution

## Example

```bash
python xc-count-lb-objects-by-label.py \
  --base_url https://acme.console.ves.volterra.io \
  --api_token ABC123 \
  --days 30 \
  --label application \
  --output lb_stats.csv
```

Notes:

* Feature flags apply only to HTTP load balancers
* HTTP request counts are calculated from request rate metrics
* TCP load balancers will have blank values for HTTP-only fields
* Unlabeled load balancers will show `unlabeled` in the label column

## How HTTP Request Counts Work

For each HTTP load balancer:

1. The script queries the XC Graph API for HTTP_REQUEST_RATE
2. Retrieves requests per second for that load balancer
3. Multiplies by the selected time window (default 30 days)
4. Produces total request count per load balancer

## Performance Notes

Large environments may take time to run because:

* Every namespace is scanned
* Every load balancer is queried individually
* Request metrics are retrieved per load balancer

Progress is displayed while running unless disabled with:

```
--no-progress
```

## Error Handling

If any API call fails:

* The script continues processing
* Errors are recorded in the `issues` column of the CSV

This ensures partial data is still returned even if some calls fail.

## Purpose

This script is intended to provide operational visibility into:

* Load balancer usage
* Application ownership via labels
* Security feature adoption
* Request volume by load balancer

