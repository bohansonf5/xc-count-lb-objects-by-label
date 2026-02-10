import argparse
import csv
import json
import sys
import time
from typing import Dict, Iterable, List, Optional, Tuple, Any

try:
    import requests  # type: ignore
except ImportError:
    sys.stderr.write(
        "The 'requests' package is required to run this script.\n"
        "Install it with: pip install requests\n"
    )
    raise


def list_namespaces(
    base_url: str,
    api_token: str,
    verify_ssl: bool = True,
) -> Optional[List[str]]:

    url = f"{base_url.rstrip('/')}/api/web/namespaces"
    headers = {"Authorization": f"APIToken {api_token}"}
    try:
        resp = requests.get(url, headers=headers, verify=verify_ssl, timeout=30)
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except json.JSONDecodeError:
        return None
    items = data.get("items")
    if not isinstance(items, list):
        return None
    namespaces: List[str] = []
    for item in items:
        name = item.get("name")
        namespaces.append(name)
    return namespaces


def list_objects(
    base_url: str,
    api_token: str,
    namespace: str,
    kind: str,
    verify_ssl: bool = True,
) -> Optional[List[dict]]:

    url = f"{base_url.rstrip('/')}/api/config/namespaces/{namespace}/{kind}"
    headers = {"Authorization": f"APIToken {api_token}"}
    try:
        resp = requests.get(url, headers=headers, verify=verify_ssl, timeout=30)
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except json.JSONDecodeError:
        return None
    items = data.get("items")
    return items

def get_http_lb_detail(
    base_url: str,
    api_token: str,
    namespace: str,
    lb_name: str,
    verify_ssl: bool = True,
) -> Optional[dict]:

    url = f"{base_url.rstrip('/')}/api/config/namespaces/{namespace}/http_loadbalancers/{lb_name}"
    headers = {"Authorization": f"APIToken {api_token}"}
    try:
        resp = requests.get(url, headers=headers, verify=verify_ssl, timeout=30)
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    try:
        return resp.json()
    except json.JSONDecodeError:
        return None


def is_waf_enabled(spec: dict) -> bool:
    for key in spec:
        if key == "disable_waf":
            return False
    # If no disable flag is set, we treat this as enabled
    return True


def is_malicious_detection_enabled(spec: dict) -> bool:
    for key in spec:
        if key == "disable_malicious_user_detection":
            return False
    # If no disable flag is set, we treat detection as enabled
    return True


def is_malicious_protection_enabled(spec: dict) -> bool:
    for key in spec:
        if key == "enable_challenge":
            if "malicious_user_mitigation" in spec["enable_challenge"]:
                return True
    # If enable challenge isn't set, we treat this as enabled
    return False

def is_api_discovery_enabled(spec: dict) -> bool:
    for key in spec:
        if key == "disable_api_discovery":
            return False
    # If no disable flag is set, we treat this as enabled
    return True

def extract_application_label(obj: dict, label_key: str) -> str:

    raw_label_value: Optional[str] = None
    labels = obj.get("labels")
    if not labels:
        return "unlabeled"
    if isinstance(labels, dict) and label_key in labels:
        raw_label_value = labels.get(label_key)
    if isinstance(raw_label_value, str) and raw_label_value:
        return raw_label_value
    return "unlabeled"

def get_lb_http_requests_count(
    base_url: str,
    api_token: str,
    namespace: str,
    lb_name: str,
    start_time: int,
    end_time: int,
    verify_ssl: bool = True,
) -> Tuple[Optional[int], Optional[str]]:

    # Compute duration in seconds
    duration = end_time - start_time
    if duration <= 0:
        return None, "Invalid time range for HTTP request count"
    # Construct payload according to API specification
    payload = {
        "field_selector": {
            "node": {
                "metric": {
                    "downstream": ["HTTP_REQUEST_RATE"]
                },
                "healthscore": {
                    "types": ["HEALTHSCORE_OVERALL"]
                },
            }
        },
        "step": f"{duration}s",
        "end_time": str(end_time),
        "start_time": str(start_time),
        "label_filter": [
            {
                "label": "LABEL_VHOST",
                "op": "EQ",
                "value": f"ves-io-http-loadbalancer-{lb_name}",
            }
        ],
        "group_by": ["VHOST", "NAMESPACE"],
    }
    url = f"{base_url.rstrip('/')}/api/data/namespaces/{namespace}/graph/service"
    session = requests.Session()
    session.headers.update({"Authorization": f"APIToken {api_token}"})
    session.verify = verify_ssl
    try:
        resp = session.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return None, f"Graph service request failed for {lb_name}: {exc}"
    nodes: List[Any] = []
    root_data = data.get("data", data)
    nodes = root_data.get("nodes") or []
    total_requests: float = 0.0
    SECONDS_PER_MONTH = 24 * 60 * 60 * 30
    for node in nodes:
        metric_data = (
            node.get("data", {})
            .get("metric", {})
            .get("downstream", [])
        )
        for metric in metric_data:
            value_obj = metric.get("value", {})
            raw_samples = value_obj.get("raw", [])
            for sample in raw_samples:
                val = sample.get("value")
                rate = float(val)
                total_requests += rate * SECONDS_PER_MONTH

    if total_requests > 0:
        return int(total_requests), None
    else:
        return None, "No HTTP request rate metrics found in graph/service response"

def collect_lb_entries(
    base_url: str,
    api_token: str,
    namespace: str,
    start_time: int,
    end_time: int,
    label_key: str,
    verify_ssl: bool = True,
) -> List[Dict[str, object]]:

    rows: List[Dict[str, object]] = []
    general_issues: List[str] = []

    # Process HTTP load balancers
    http_lbs = list_objects(base_url, api_token, namespace, "http_loadbalancers", verify_ssl)
    if http_lbs is None:
        general_issues.append("Failed to list http_loadbalancers")
    else:
        for lb in http_lbs:
            # Extract label value for this load balancer
            label_value = extract_application_label(lb, label_key)
            # Determine LB name
            lb_name = lb.get("name")
            row_issues: List[str] = []
            # Fetch full spec
            detail = get_http_lb_detail(base_url, api_token, namespace, lb_name, verify_ssl)
            api_enabled = 0
            waf_enabled = 0
            malicious_det_enabled = 0
            malicious_prot_enabled = 0
            if not detail or not isinstance(detail, dict):
                row_issues.append(f"Failed to fetch http_loadbalancer '{lb_name}' details")
            else:
                spec = detail.get("spec") or detail.get("get_spec")
                if not isinstance(spec, dict):
                    row_issues.append(f"Missing spec in http_loadbalancer '{lb_name}'")
                else:
                    api_enabled = 1 if is_api_discovery_enabled(spec) else 0
                    waf_enabled = 1 if is_waf_enabled(spec) else 0
                    malicious_det_enabled = 1 if is_malicious_detection_enabled(spec) else 0
                    malicious_prot_enabled = 1 if is_malicious_protection_enabled(spec) else 0
            # Retrieve HTTP request count for this LB
            http_req_count = ""
            lb_req_count, lb_issue = get_lb_http_requests_count(
                base_url,
                api_token,
                namespace,
                lb_name,
                start_time,
                end_time,
                verify_ssl,
            )
            if lb_issue:
                row_issues.append(lb_issue)
            if lb_req_count is not None:
                http_req_count = lb_req_count
            row = {
                "namespace": namespace,
                "lb_name": lb_name,
                "application_label": label_value,
                "lb_type": "http",
                "api_discovery_enabled": api_enabled,
                "waf_enabled": waf_enabled,
                "malicious_detection_enabled": malicious_det_enabled,
                "malicious_protection_enabled": malicious_prot_enabled,
                "http_requests": http_req_count,
                "issues": "; ".join(sorted(set(row_issues))) if row_issues else "",
            }
            rows.append(row)

    # Process TCP load balancers
    tcp_lbs = list_objects(base_url, api_token, namespace, "tcp_loadbalancers", verify_ssl)
    if tcp_lbs is None:
        general_issues.append("Failed to list tcp_loadbalancers")
    else:
        for lb in tcp_lbs:
            label_value = extract_application_label(lb, label_key)
            lb_name: Optional[str] = None
            if isinstance(lb, dict):
                lb_name = lb.get("name")
                if not lb_name and isinstance(lb.get("metadata"), dict):
                    lb_name = lb["metadata"].get("name")
            if not lb_name or not isinstance(lb_name, str):
                continue
            # For TCP load balancers, feature flags and HTTP requests are not applicable
            row = {
                "namespace": namespace,
                "lb_name": lb_name,
                "application_label": label_value,
                "lb_type": "tcp",
                "api_discovery_enabled": "",
                "waf_enabled": "",
                "malicious_detection_enabled": "",
                "malicious_protection_enabled": "",
                "http_requests": "",
                "issues": "",
            }
            rows.append(row)

    # If there were general issues and no rows were produced, create a single row to record the issues
    if not rows and general_issues:
        rows.append(
            {
                "namespace": namespace,
                "lb_name": "",
                "application_label": "",
                "lb_type": "",
                "api_discovery_enabled": "",
                "waf_enabled": "",
                "malicious_detection_enabled": "",
                "malicious_protection_enabled": "",
                "http_requests": "",
                "issues": "; ".join(sorted(set(general_issues))),
            }
        )
    # Propagate any general issues to each row (append to per‑row issues)
    if general_issues:
        general_issue_str = "; ".join(sorted(set(general_issues)))
        for row in rows:
            row_issues = row.get("issues")
            if row_issues:
                row["issues"] = f"{row_issues}; {general_issue_str}"
            else:
                row["issues"] = general_issue_str

    return rows


def write_csv(path: str, rows: Iterable[Dict[str, object]]) -> None:
    rows = list(rows)
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "List namespaces and collect statistics for each load balancer in "
            "F5 Distributed Cloud (XC).  Instead of aggregating by namespace, this "
            "script produces a CSV row for every HTTP and TCP load balancer.  "
            "Each row records the namespace, load balancer name, the value of "
            "the chosen label (default: 'application'), the type of load balancer "
            "(HTTP or TCP), whether various security features are enabled (for "
            "HTTP load balancers), the total number of HTTP requests over the "
            "specified time window (for HTTP load balancers), and any issues "
            "encountered."
        )
    )
    parser.add_argument(
        "--base_url",
        required=True,
        help="Base URL of the XC API (e.g., https://tenant.console.ves.volterra.io)",
    )
    parser.add_argument(
        "--api_token",
        required=True,
        help="API token for Authorization header",
    )
    parser.add_argument(
        "--output",
        default="xc_usage_stats.csv",
        help="Path to the output CSV file (default: xc_usage_stats.csv)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL certificate verification",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help=(
            "Number of days in the past to include when calculating HTTP request "
            "counts (default: 30).  The time range spans from now minus this "
            "number of days to the current time."
        ),
    )
    parser.add_argument(
        "--label",
        default="application",
        help=(
            "The label key to extract from each load balancer (default: 'application')."
        ),
    )

    parser.add_argument(
        "--no-progress",
        action="store_true",
        help=(
            "Suppress progress messages.  By default the script writes a line to stderr "
            "for each namespace indicating progress.  Specify this flag to disable "
            "those messages."
        ),
    )
    args = parser.parse_args(argv)

    verify_ssl = not args.insecure

    namespaces = list_namespaces(args.base_url, args.api_token, verify_ssl)
    if namespaces is None:
        sys.stderr.write("Failed to list namespaces. Check your base URL and API token.\n")
        return 1
    if not namespaces:
        sys.stderr.write("No namespaces found.\n")
        return 1

    # Compute time range for HTTP request counts
    now_ts = int(time.time())
    start_ts = now_ts - args.days * 24 * 60 * 60
    end_ts = now_ts
    rows: List[Dict[str, object]] = []
    total_namespaces = len(namespaces)
    for idx, ns in enumerate(namespaces, start=1):
        # Print progress message unless suppressed
        if not args.no_progress:
            remaining = total_namespaces - idx
            sys.stderr.write(
                f"[{idx}/{total_namespaces}] Processing namespace '{ns}' ({remaining} remaining)\n"
            )
        try:
            lb_rows = collect_lb_entries(
                args.base_url,
                args.api_token,
                ns,
                start_ts,
                end_ts,
                label_key=args.label,
                verify_ssl=verify_ssl,
            )
            rows.extend(lb_rows)
        except Exception as exc:
            # On unexpected failure, record a single row with an issue
            rows.append(
                {
                    "namespace": ns,
                    "lb_name": "",
                    "application_label": "",
                    "lb_type": "",
                    "api_discovery_enabled": "",
                    "waf_enabled": "",
                    "malicious_detection_enabled": "",
                    "malicious_protection_enabled": "",
                    "http_requests": "",
                    "issues": str(exc),
                }
            )
    # If no rows were produced, bail
    if not rows:
        sys.stderr.write("No statistics were generated.\n")
        return 1
    # Determine field names for per-load-balancer rows
    fieldnames = [
        "namespace",
        "lb_name",
        "application_label",
        "lb_type",
        "api_discovery_enabled",
        "waf_enabled",
        "malicious_detection_enabled",
        "malicious_protection_enabled",
        "http_requests",
        "issues",
    ]
    try:
        write_csv(args.output, rows)
        print(
            f"Wrote statistics for {len(rows)} load balancers across {total_namespaces} namespaces to {args.output}"
        )
    except Exception as exc:
        sys.stderr.write(f"Failed to write CSV: {exc}\n")
        return 1
    return 0


if __name__ == "__main__": 
    raise SystemExit(main())