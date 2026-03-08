#!/usr/bin/env python3
"""
REK MCP Server
Exposes REK reconnaissance capabilities as MCP tools over three transports:

  StdIO (default)       — JSON-RPC 2.0 over stdin/stdout
  SSE (--http)          — GET /sse  +  POST /messages   (MCP 2024-11-05)
  Streamable HTTP (--http) — POST /mcp                  (MCP 2025-03-26)

Usage:
    python3 rek_mcp_server.py                        # StdIO
    python3 rek_mcp_server.py --http                 # HTTP on 0.0.0.0:8000
    python3 rek_mcp_server.py --http --port 3000     # HTTP on custom port
    python3 rek_mcp_server.py --http --host 127.0.0.1 --port 3000

HTTP dependencies (not required for StdIO):
    pip install fastapi "uvicorn[standard]" sse-starlette
"""

import sys
import json
import asyncio
import io
import os
import contextlib
import logging
import logging.handlers
import argparse
import uuid
import functools
import time
from datetime import datetime, timezone
from typing import Any, Optional

# Suppress all warnings so they don't corrupt StdIO JSON stream
import warnings
warnings.filterwarnings("ignore")

# Ensure REK modules are importable from the same directory
_SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _SERVER_DIR)

# ---------------------------------------------------------------------------
# File logger (safe to use in all transports — never writes to stdout)
# ---------------------------------------------------------------------------

_LOG_PATH = os.path.join(_SERVER_DIR, "logs", "rek_mcp_server.log")
os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)

_log = logging.getLogger("rek_mcp_server")
_log.setLevel(logging.DEBUG)
_log.propagate = False  # isolated — won't reach root logger or stdout

_fh = logging.handlers.RotatingFileHandler(
    _LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_log.addHandler(_fh)

# Suppress root logger (and all rek module loggers) without a process-wide
# disable that would also kill our file logger above
logging.getLogger().setLevel(logging.CRITICAL + 1)


# ---------------------------------------------------------------------------
# Recon state graph (persistent intelligence store)
# ---------------------------------------------------------------------------

from rek_state import state_graph as _state

# ---------------------------------------------------------------------------
# State update dispatcher — called after every successful tool result
# ---------------------------------------------------------------------------

def _update_state(tool_name: str, args: dict, result_json: str) -> None:
    """
    Parse a successful tool result JSON and push normalized entities into the
    persistent state graph.  All errors are swallowed so a state write failure
    never surfaces to the caller.
    """
    try:
        result = json.loads(result_json)
    except (json.JSONDecodeError, TypeError):
        return
    if result.get("exit_status") != "success":
        return

    try:
        if tool_name == "enumerate_subdomains":
            target = result.get("target", "")
            if target:
                _state.upsert_target(target)
            for sub in result.get("subdomains_discovered", []):
                _state.upsert_subdomain(sub, target, "enumerate_subdomains")
            for sub in result.get("subdomains_validated", []):
                _state.upsert_subdomain(sub, target, "enumerate_subdomains")

        elif tool_name == "run_port_scan":
            for entry in result.get("open_ports", []):
                host = entry.get("host", "")
                port = entry.get("port")
                if host and port:
                    _state.upsert_service(host, int(port))

        elif tool_name in ("run_endpoint_scan", "scan_directories"):
            if tool_name == "run_endpoint_scan":
                for url in result.get("endpoints", []):
                    _state.upsert_endpoint(url)
            else:
                for finding in result.get("findings", []):
                    for path_entry in finding.get("paths", []):
                        url = path_entry.get("url", "")
                        if url:
                            _state.upsert_endpoint(url)

        elif tool_name == "check_http_status":
            # Results live in the CSV; extract server tech from it if present
            output_file = result.get("output_file", "")
            if output_file and os.path.exists(output_file):
                import csv as _csv
                try:
                    with open(output_file, "r", encoding="utf-8", newline="") as fh:
                        reader = _csv.DictReader(fh)
                        for row in reader:
                            host = row.get("Subdomain", "").strip()
                            server = row.get("Server", "").strip()
                            if host and server and server not in ("-", ""):
                                _state.upsert_technology(host, [server])
                except Exception:
                    pass

    except Exception as e:
        _log.debug("State update skipped for %s: %s", tool_name, e)


# Redirect sys.stderr to the log file so nothing leaks to the StdIO stream
class _StderrToLog:
    def write(self, msg: str) -> None:
        msg = msg.strip()
        if msg:
            _log.warning("[stderr] %s", msg)

    def flush(self) -> None:
        pass

# ---------------------------------------------------------------------------
# Structured output helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    """ISO 8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _ok(tool: str, start: float, **fields) -> str:
    """Serialize a successful structured tool result to a JSON string."""
    return json.dumps({
        "tool": tool,
        "timestamp": _ts(),
        "execution_time_seconds": round(time.time() - start, 2),
        "exit_status": "success",
        **fields,
    }, indent=2)


def _err(tool: str, start: float, message: str, **fields) -> str:
    """Serialize a failure structured tool result to a JSON string."""
    return json.dumps({
        "tool": tool,
        "timestamp": _ts(),
        "execution_time_seconds": round(time.time() - start, 2),
        "exit_status": "failure",
        "error": message,
        **fields,
    }, indent=2)


def _domain_gate_check(asset: str, tool: str, start: float) -> Optional[str]:
    """
    Domain approval gate for MCP tool handlers.

    Consults the domain safety gate before any active tool invocation.
    Returns a ready-to-return _err() JSON string if the asset's root domain
    has not been approved, or None if the asset is allowed.

    This check runs BEFORE the scope gate. LLM reasoning must never bypass it.
    """
    from rek_domain_gate import domain_gate
    allowed = domain_gate.domain_safety_gate(
        asset, discovered_from="mcp_tool", discovery_method="mcp_invocation"
    )
    if not allowed:
        status = domain_gate.get_status(asset)
        _log.info(
            "DOMAIN_GATE_BLOCKED_MCP tool=%s asset=%s root=%s status=%s action=blocked",
            tool, asset, status.get("root", "?"), status.get("status", "pending"),
        )
        return _err(
            tool, start,
            f"domain_gate_blocked: {asset} — root domain '{status.get('root', '?')}' "
            f"is {status.get('status', 'pending')}. Use approve_domain to allow scanning.",
            asset=asset,
            root_domain=status.get("root"),
            gate_status=status.get("status"),
        )
    return None


def _scope_check(asset: str, tool: str, start: float) -> Optional[str]:
    """
    Scope gate for MCP tool handlers.

    Consults the file-based scope guard before any active tool invocation.
    Returns a ready-to-return _err() JSON string if the asset is out of
    scope, or None if the asset is allowed.

    This function must be called at the top of every active scan handler.
    LLM reasoning must never bypass this check.
    """
    from rek_scope import scope_guard
    result = scope_guard.in_scope(asset)
    if not result["allowed"]:
        import logging
        logging.getLogger("rek_mcp_server").info(
            "SCOPE_BLOCKED_MCP tool=%s asset=%s reason=%s action=blocked",
            tool, result["asset"], result["scope_reason"],
        )
        return _err(
            tool, start,
            f"out_of_scope: {result['asset']} — {result['scope_reason']}",
            asset=result["asset"],
            scope_reason=result["scope_reason"],
        )
    return None


# ---------------------------------------------------------------------------
# Tool definitions (MCP schema)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "enumerate_subdomains",
        "description": (
            "Enumerate subdomains for a target domain using DNS brute-force, "
            "certificate transparency logs (crt.sh), and DNSDumpster. "
            "Returns discovered and DNS-validated subdomains."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain (e.g., example.com)"
                },
                "wordlist_path": {
                    "type": "string",
                    "description": "Path to custom subdomain wordlist file (optional)"
                },
                "concurrency": {
                    "type": "integer",
                    "description": "Max concurrent DNS queries (default: 50)",
                    "default": 50
                },
                "timeout": {
                    "type": "integer",
                    "description": "Request timeout in seconds (default: 10)",
                    "default": 10
                },
                "retries": {
                    "type": "integer",
                    "description": "Number of retries for failed requests (default: 3)",
                    "default": 3
                },
                "github_token": {
                    "type": "string",
                    "description": "GitHub Personal Access Token for parallel email search (optional)"
                },
                "output_file": {
                    "type": "string",
                    "description": "Output file path for results (default: <domain>_results.txt)"
                },
                "resolvers": {
                    "type": "string",
                    "description": "Comma-separated custom DNS resolver IPs to use (e.g., 8.8.8.8,1.1.1.1)"
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "check_http_status",
        "description": (
            "Check HTTP/HTTPS status codes, page titles, and server headers "
            "for a list of subdomains or URLs read from a file."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_file": {
                    "type": "string",
                    "description": "Path to file containing one URL/subdomain per line"
                },
                "output_file": {
                    "type": "string",
                    "description": "Output CSV file path (default: http_results.csv)",
                    "default": "http_results.csv"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Request timeout in seconds (default: 10)",
                    "default": 10
                },
                "concurrency": {
                    "type": "integer",
                    "description": "Max concurrent requests (default: 100)",
                    "default": 100
                }
            },
            "required": ["input_file"]
        }
    },
    {
        "name": "scan_directories",
        "description": (
            "Scan for directories and files on web servers using wordlists. "
            "Accepts either a single URL or a CSV file from check_http_status filtered by status codes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Single target URL to scan (e.g., https://example.com)"
                },
                "input_file": {
                    "type": "string",
                    "description": "CSV file from check_http_status to filter and scan URLs"
                },
                "status_codes": {
                    "type": "string",
                    "description": "Comma-separated HTTP status codes to include (e.g., 200,301,403)"
                },
                "dir_wordlist": {
                    "type": "string",
                    "description": "Path to custom wordlist file for directory scanning (optional)"
                },
                "depth": {
                    "type": "integer",
                    "description": "Maximum crawl depth, 1-10 (default: 5)",
                    "default": 5
                },
                "timeout": {
                    "type": "integer",
                    "description": "Request timeout in seconds (default: 10)",
                    "default": 10
                },
                "concurrency": {
                    "type": "integer",
                    "description": "Max concurrent requests (default: 50)",
                    "default": 50
                },
                "extensions": {
                    "type": "string",
                    "description": "Comma-separated file extensions to filter results (e.g., .php,.asp,.env,.bak)"
                }
            }
        }
    },
    {
        "name": "search_emails",
        "description": (
            "Search for email addresses associated with a domain or GitHub organization/user. "
            "Optionally checks discovered emails against Have I Been Pwned breach database."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "email_domain": {
                    "type": "string",
                    "description": "Domain to search emails for (e.g., example.com)"
                },
                "username": {
                    "type": "string",
                    "description": "GitHub username to search commit history for emails"
                },
                "org": {
                    "type": "string",
                    "description": "GitHub organization name to search"
                },
                "token": {
                    "type": "string",
                    "description": "GitHub Personal Access Token (increases rate limits)"
                },
                "hibp_key": {
                    "type": "string",
                    "description": "Have I Been Pwned API key for breach checking (optional)"
                },
                "limit_commits": {
                    "type": "integer",
                    "description": "Max commits to scan per repository (default: 50)",
                    "default": 50
                },
                "skip_forks": {
                    "type": "boolean",
                    "description": "Skip forked repositories (default: true)",
                    "default": True
                },
                "output_file": {
                    "type": "string",
                    "description": "Output CSV file path (default: email_results.csv)",
                    "default": "email_results.csv"
                },
                "domain_filter": {
                    "type": "string",
                    "description": "Regex pattern to filter returned emails by domain (e.g., gmail\\.com|yahoo\\.com)"
                }
            }
        }
    },
    {
        "name": "map_org_affiliations",
        "description": (
            "Map cross-organizational affiliations from a GitHub target (user or org) "
            "and discover exposed API surfaces across affiliated repositories. "
            "Phase 1 resolves the target entity via GitHub API, enumerates members, "
            "and identifies bridge members — individuals active in the target org AND "
            "external orgs — representing potential proxy/supply-chain exposure vectors. "
            "Affiliated orgs are ranked by shared member count. "
            "Phase 2 scans repos across the target and top affiliated orgs for API spec "
            "files (OpenAPI/Swagger/.env/config), extracts endpoint lists, and searches "
            "code for route definitions and credential pattern exposures. "
            "Outputs: affiliations CSV, bridge members JSON, API findings CSV, and a flat "
            "endpoints.txt feedable directly into check_http_status."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "GitHub username or organization login to map"
                },
                "token": {
                    "type": "string",
                    "description": "GitHub Personal Access Token (required for code search; increases rate limits)"
                },
                "max_members": {
                    "type": "integer",
                    "description": "Max members to map for affiliation graph (default: 100)",
                    "default": 100
                },
                "max_repos": {
                    "type": "integer",
                    "description": "Max repos to scan per org for API surface (default: 30)",
                    "default": 30
                },
                "output_file": {
                    "type": "string",
                    "description": "Base path for output files (default: org_intel_results.csv)",
                    "default": "org_intel_results.csv"
                },
                "scan_affiliated_count": {
                    "type": "integer",
                    "description": "How many top affiliated orgs receive the Phase 2 API surface scan (default: 5)",
                    "default": 5
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "run_playbook",
        "description": (
            "Run ONE automated reconnaissance playbook against a target domain. "
            "Three independent playbooks are available — each must be called separately: "
            "'v1' (advanced: subdomain enum, HTTP probing, port scanning, JS analysis, reporting), "
            "'v2' (URL crawler: focused on crawling and URL discovery), "
            "'standard' (baseline recon pipeline). "
            "To run all three, call this tool three times with version='v1', 'v2', and 'standard' respectively. "
            "Requires bash and external tools installed via install-script.sh."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain (e.g., example.com)"
                },
                "version": {
                    "type": "string",
                    "description": "Playbook version to run: 'v1' (advanced), 'v2' (URL crawler), or 'standard'",
                    "enum": ["v1", "v2", "standard"],
                    "default": "v1"
                },
                "threads": {
                    "type": "integer",
                    "description": "Thread count for scanning tools (default: 100)",
                    "default": 100
                },
                "chaos_key": {
                    "type": "string",
                    "description": "Chaos Project API key (optional)"
                },
                "github_token": {
                    "type": "string",
                    "description": "GitHub Personal Access Token (optional)"
                },
                "skip_portscan": {
                    "type": "boolean",
                    "description": "Skip port scanning phase (default: false)",
                    "default": False
                },
                "skip_jsanalysis": {
                    "type": "boolean",
                    "description": "Skip JavaScript analysis phase (default: false)",
                    "default": False
                },
                "output_dir": {
                    "type": "string",
                    "description": "Custom output directory for playbook results (default: server working directory)"
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "run_port_scan",
        "description": (
            "Scan one or more hosts for open ports using naabu. "
            "Returns a structured list of open host:port pairs. "
            "Requires naabu installed (via playbook/install-script.sh). "
            "Output feeds naturally into run_endpoint_scan or check_http_status."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Single target host, IP, domain, or CIDR range"
                },
                "hosts_file": {
                    "type": "string",
                    "description": "Path to file with one host per line (alternative to host)"
                },
                "ports": {
                    "type": "string",
                    "description": "Comma-separated ports or ranges to scan (default: common web ports)",
                    "default": "80,443,3000,5000,8000,8001,8080,8081,8088,8443,8888,9000"
                },
                "concurrency": {
                    "type": "integer",
                    "description": "Max concurrent probes (default: 100)",
                    "default": 100
                },
                "timeout": {
                    "type": "integer",
                    "description": "Probe timeout in seconds (default: 10)",
                    "default": 10
                },
                "output_file": {
                    "type": "string",
                    "description": "Output file path for raw results (default: port_results.txt)",
                    "default": "port_results.txt"
                }
            }
        }
    },
    {
        "name": "run_endpoint_scan",
        "description": (
            "Crawl web targets for endpoints and URLs using katana (active) or gau (passive). "
            "Returns a structured list of discovered endpoints. "
            "Requires katana or gau installed (via playbook/install-script.sh). "
            "Output feeds naturally into check_http_status or scan_directories."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Single target URL to crawl (e.g., https://example.com)"
                },
                "urls_file": {
                    "type": "string",
                    "description": "Path to file with one URL per line (alternative to url)"
                },
                "scanner": {
                    "type": "string",
                    "description": "Crawler to use: 'katana' (active crawl) or 'gau' (passive URL fetch)",
                    "enum": ["katana", "gau"],
                    "default": "katana"
                },
                "depth": {
                    "type": "integer",
                    "description": "Maximum crawl depth for katana (default: 5)",
                    "default": 5
                },
                "concurrency": {
                    "type": "integer",
                    "description": "Max concurrent requests (default: 50)",
                    "default": 50
                },
                "timeout": {
                    "type": "integer",
                    "description": "Request timeout in seconds (default: 10)",
                    "default": 10
                },
                "output_file": {
                    "type": "string",
                    "description": "Output file path for discovered endpoints (default: endpoint_results.txt)",
                    "default": "endpoint_results.txt"
                }
            }
        }
    },
    {
        "name": "query_target_state",
        "description": (
            "Return full aggregated recon intelligence for a target from the persistent state graph. "
            "Includes all known subdomains, open services, discovered endpoints, and technology stack. "
            "Call this before running new scans to understand what is already known."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain to query (e.g., example.com)"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "query_subdomains",
        "description": (
            "Return all subdomains known for a target from the persistent state graph. "
            "Faster than re-running enumeration when intelligence already exists."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain to query (e.g., example.com)"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "query_services",
        "description": (
            "Return all known open ports and services for a specific host from the persistent state graph."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Hostname or IP to query (e.g., api.example.com)"
                }
            },
            "required": ["host"]
        }
    },
    {
        "name": "run_incremental_recon",
        "description": (
            "Run reconnaissance only against assets not yet seen in the state graph. "
            "Phase 1: enumerate subdomains and identify which are new. "
            "Phase 2: port scan only new subdomains. "
            "Phase 3: endpoint scan new hosts with open web ports. "
            "Skips assets already known to the state graph to avoid redundant work. "
            "All discoveries are persisted automatically."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain to run incremental recon against"
                },
                "wordlist_path": {
                    "type": "string",
                    "description": "Path to custom subdomain wordlist (optional)"
                },
                "github_token": {
                    "type": "string",
                    "description": "GitHub token for subdomain enumeration (optional)"
                },
                "ports": {
                    "type": "string",
                    "description": "Ports to scan on new hosts (default: common web ports)",
                    "default": "80,443,3000,5000,8000,8001,8080,8081,8088,8443,8888,9000"
                },
                "skip_port_scan": {
                    "type": "boolean",
                    "description": "Skip port scanning phase (default: false)",
                    "default": False
                },
                "skip_endpoint_scan": {
                    "type": "boolean",
                    "description": "Skip endpoint scanning phase (default: false)",
                    "default": False
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "get_prioritized_findings",
        "description": (
            "Analyze recon state graph data for a target and return findings ranked by "
            "investigative interest using deterministic rule-based scoring. "
            "Scoring rules: subdomain keywords (+5 per match: admin, internal, dev, staging, "
            "beta, debug, test, backup, old), suspicious ports (+4 each: 3000, 5000, 5601, "
            "6379, 8081, 9000, 9200, 2375), sensitive endpoints (+5 per pattern: /admin, "
            "/debug, /.git, /config, /graphql, /internal, /api/internal), exposed services "
            "(+4 each: Jenkins, Grafana, Elasticsearch, Kibana, phpMyAdmin). "
            "Returns three priority buckets: high (>=10), medium (>=5), low (<5). "
            "Run enumerate_subdomains, run_port_scan, and run_endpoint_scan first to populate state."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain to analyze (e.g., example.com)"
                },
                "min_score": {
                    "type": "integer",
                    "description": "Exclude findings below this score (default: 0 — return all)",
                    "default": 0
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "get_top_targets",
        "description": (
            "Return the top-N highest-scoring investigation targets for a domain "
            "from the recon intelligence engine. Combines all priority tiers sorted "
            "by score descending. Useful for deciding where to focus next."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain to query (e.g., example.com)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of findings to return (default: 10)",
                    "default": 10
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "expand_target",
        "description": (
            "Run passive target expansion against one or more public intelligence "
            "sources (crt.sh CT logs, TLS SANs, BGPView ASN, HackerTarget passive "
            "DNS, ThreatMiner passive DNS). Discovered subdomains and CIDR blocks are "
            "written into the persistent state graph. No active probes are sent to the "
            "target — all data comes from third-party public APIs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Root domain to expand (e.g., example.com)"
                },
                "org": {
                    "type": "string",
                    "description": "Organisation name for ASN/BGPView lookup (optional)"
                },
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Expansion sources to run. Valid values: ct, san, asn, "
                        "hackertarget, threatminer. Defaults to all sources."
                    )
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "list_discovered_assets",
        "description": (
            "Return all assets discovered and stored in the recon state graph for a "
            "target: subdomains, open services, crawled endpoints, tech stack, and "
            "infrastructure CIDR blocks. Useful for a full inventory snapshot before "
            "deciding on next recon steps."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain to query (e.g., example.com)"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "schedule_target",
        "description": (
            "Apply deterministic planning rules to a target and enqueue recon tasks "
            "into the scheduler queue. Rules inspect the state graph for new/stale "
            "assets and high-priority findings, then produce a prioritised task list. "
            "No tasks are executed — use run_scheduler to execute. "
            "Modes: standard (default), passive_only, review_queue_only."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Root domain to plan for (e.g., example.com)"
                },
                "mode": {
                    "type": "string",
                    "description": (
                        "Scheduler mode: standard | passive_only | "
                        "review_queue_only | immediate_execute (default: standard)"
                    )
                },
                "org": {
                    "type": "string",
                    "description": "Organisation name for ASN expansion (optional)"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "run_scheduler",
        "description": (
            "Execute pending scheduled tasks from the recon scheduler queue. Tasks "
            "are run in priority order with dependency checking. Returns a summary "
            "of completed and failed tasks. Use schedule_target first to populate "
            "the queue. Optionally filter by target domain."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Only run tasks for this target (optional — default: all targets)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of tasks to execute (default: 10)",
                    "default": 10
                },
                "mode": {
                    "type": "string",
                    "description": (
                        "Execution mode: standard | passive_only | "
                        "review_queue_only (default: standard)"
                    )
                }
            },
            "required": []
        }
    },
    {
        "name": "get_scheduler_status",
        "description": (
            "Return a summary of the current scheduler queue: counts of pending, "
            "running, completed, skipped, deferred, and failed tasks, plus the "
            "timestamp of the last scheduler run."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_target_plan",
        "description": (
            "Return the current pending task queue for a specific target without "
            "executing anything. Shows task type, tool, priority, reason, and "
            "dependency information for all queued tasks."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain to query (e.g., example.com)"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "run_false_positive_suppression",
        "description": (
            "Evaluate all discovered subdomains for a target and apply deterministic "
            "suppression rules. Assets are marked as suppressed, deferred, active, or "
            "verified in the state graph without being deleted. Suppressed assets are "
            "excluded from normal scheduler queuing. Returns a summary with per-status "
            "counts and a full audit log of status changes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain to evaluate (e.g., example.com)"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "list_suppressed_assets",
        "description": (
            "Return all suppressed, deferred, and merged subdomain assets for a "
            "target along with their suppression reasons. Use this to review what "
            "the suppression engine has excluded and decide if any need restoration."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain to query (e.g., example.com)"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "restore_asset",
        "description": (
            "Restore a suppressed or deferred subdomain asset to candidate status, "
            "making it eligible for normal scheduling again. The suppression decision "
            "is preserved in logs but overridden in the state graph. Useful for "
            "manually reviewing and reinstating assets that were incorrectly suppressed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "asset": {
                    "type": "string",
                    "description": "FQDN of the asset to restore (e.g., sub.example.com)"
                }
            },
            "required": ["asset"]
        }
    },
    {
        "name": "check_scope",
        "description": (
            "Check whether one or more assets (domains, subdomains, URLs, or IP "
            "addresses) fall within the declared recon scope configured in "
            "state/scope.json. Returns allowed status and scope reason for each "
            "asset. Out-of-scope assets are always blocked from active tool "
            "invocation — this tool lets you verify scope before running scans."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "assets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of assets to check (domains, URLs, IPs)"
                }
            },
            "required": ["assets"]
        }
    },
    {
        "name": "get_scope_config",
        "description": (
            "Return the current scope configuration: allowed domains, allowed "
            "suffixes, allowed IP ranges, excluded domains, and whether strict "
            "mode is enabled. Reflects the live state of state/scope.json."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_pending_domains",
        "description": (
            "List all root domains awaiting approval before active scanning can proceed. "
            "Returns pending, approved, and rejected domain lists with metadata. "
            "Use approve_domain or reject_domain to act on pending entries."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "approve_domain",
        "description": (
            "Approve a root domain for active scanning. Once approved, the domain "
            "safety gate will allow port scans and endpoint scans against any host "
            "within that root domain. Requires explicit human confirmation before use."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Root domain to approve for active scanning (e.g. example.com)"
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "reject_domain",
        "description": (
            "Reject a root domain, permanently blocking active scanning against any "
            "host within it. Rejected domains will not be promoted to approved even "
            "if they appear as recon targets."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Root domain to reject (e.g. example.com)"
                }
            },
            "required": ["domain"]
        }
    }
]

# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

async def tool_enumerate_subdomains(args: dict) -> str:
    t0 = time.time()
    from rek import SubdomainScanner

    domain = args["domain"]

    blocked = _domain_gate_check(domain, "enumerate_subdomains", t0)
    if blocked:
        return blocked

    blocked = _scope_check(domain, "enumerate_subdomains", t0)
    if blocked:
        return blocked

    output_file = args.get("output_file") or f"{domain}_results.txt"

    scanner = SubdomainScanner(
        timeout=args.get("timeout", 10),
        wordlist_path=args.get("wordlist_path"),
        concurrency=args.get("concurrency", 50),
        retries=args.get("retries", 3),
        silent=True
    )
    if args.get("resolvers"):
        resolver_list = [r.strip() for r in args["resolvers"].split(",") if r.strip()]
        if resolver_list and hasattr(scanner, "resolvers"):
            scanner.resolvers = resolver_list

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        await scanner.enumerate_subdomains(
            domain=domain,
            output_file=output_file,
            github_token=args.get("github_token")
        )

    all_subs = sorted(scanner.subdomains)
    validated = sorted(scanner.validated_subdomains)

    return _ok("enumerate_subdomains", t0,
        target=domain,
        output_file=output_file,
        total_discovered=len(all_subs),
        total_validated=len(validated),
        subdomains_discovered=all_subs[:500],
        subdomains_validated=validated,
    )


async def tool_check_http_status(args: dict) -> str:
    t0 = time.time()
    from rek import HTTPStatusChecker

    input_file = args["input_file"]
    output_file = args.get("output_file", "http_results.csv")

    if not os.path.exists(input_file):
        return _err("check_http_status", t0, f"Input file not found: {input_file}",
                    input_file=input_file)

    checker = HTTPStatusChecker(
        timeout=args.get("timeout", 10),
        max_concurrent=args.get("concurrency", 100),
        silent=True
    )

    with open(input_file, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        return _err("check_http_status", t0, "No URLs found in input file",
                    input_file=input_file)

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        await checker.check_all_urls(urls, output_file)

    return _ok("check_http_status", t0,
        input_file=input_file,
        output_file=output_file,
        target_count=len(urls),
        output_columns=["Subdomain", "URL", "Status Code", "Title", "Server", "Error"],
    )


async def tool_scan_directories(args: dict) -> str:
    t0 = time.time()
    from rek import DirectoryScanner

    input_file = args.get("input_file")
    url = args.get("url")

    # Domain gate + scope gate: check the explicitly supplied URL before any scan begins.
    if url:
        blocked = _domain_gate_check(url, "scan_directories", t0)
        if blocked:
            return blocked
        blocked = _scope_check(url, "scan_directories", t0)
        if blocked:
            return blocked

    scanner = DirectoryScanner(
        timeout=args.get("timeout", 10),
        max_concurrent=args.get("concurrency", 50),
        max_depth=args.get("depth", 5),
        silent=True
    )
    dir_wordlist = args.get("dir_wordlist")
    status_codes = None
    if args.get("status_codes"):
        status_codes = [int(c.strip()) for c in args["status_codes"].split(",")]

    wordlist = scanner.load_wordlist(dir_wordlist)

    if status_codes and input_file:
        urls = scanner.read_urls_by_status(input_file, status_codes)
    elif url:
        urls = [url]
    else:
        return _err("scan_directories", t0, "Must provide either a url or an input_file with status_codes")

    if not urls:
        return _err("scan_directories", t0, "No URLs to scan after filtering")

    extensions_filter = None
    if args.get("extensions"):
        extensions_filter = [
            e.strip().lstrip(".").lower()
            for e in args["extensions"].split(",")
            if e.strip()
        ]

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        await scanner.scan_all_urls(urls, wordlist)

    scanner.save_results()

    findings_out = []
    for target_url, findings in scanner.results.items():
        hits = [f for f in findings if f.get("status_code") in (200, 301, 302, 403)]
        if extensions_filter:
            hits = [
                f for f in hits
                if any(
                    f["url"].lower().endswith("." + ext) or ("." + ext + "/") in f["url"].lower()
                    for ext in extensions_filter
                )
            ]
        findings_out.append({
            "target": target_url,
            "paths_found": len(hits),
            "paths": [{"status_code": f["status_code"], "url": f["url"]} for f in hits[:100]],
        })

    return _ok("scan_directories", t0,
        targets_scanned=len(scanner.results),
        extension_filter=extensions_filter,
        findings=findings_out,
    )


async def tool_search_emails(args: dict) -> str:
    t0 = time.time()
    from rek_email_search import EmailSearcher
    import csv as _csv

    output_file = args.get("output_file", "email_results.csv")
    username = args.get("org") or args.get("username")

    searcher = EmailSearcher(timeout=10, silent=True)

    def _run():
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            searcher.run(
                domain=args.get("email_domain"),
                username=username,
                token=args.get("token"),
                output_file=output_file,
                max_commits=args.get("limit_commits", 50),
                skip_forks=args.get("skip_forks", True),
                hibp_key=args.get("hibp_key")
            )

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _run)

    domain_filter = args.get("domain_filter")
    filtered_count = None
    if domain_filter and os.path.exists(output_file):
        import re as _re
        try:
            pattern = _re.compile(domain_filter, _re.IGNORECASE)
            with open(output_file, "r", encoding="utf-8", newline="") as fh:
                rows = list(_csv.reader(fh))
            header = rows[0] if rows else []
            matched = [r for r in rows[1:] if r and pattern.search(r[0])]
            with open(output_file, "w", encoding="utf-8", newline="") as fh:
                w = _csv.writer(fh)
                if header:
                    w.writerow(header)
                w.writerows(matched)
            filtered_count = len(matched)
        except Exception as fe:
            _log.warning("domain_filter post-processing failed: %s", fe)

    emails_found = 0
    if os.path.exists(output_file):
        try:
            with open(output_file, "r", encoding="utf-8", newline="") as fh:
                emails_found = max(0, sum(1 for _ in _csv.reader(fh)) - 1)
        except Exception:
            pass

    result_fields: dict = dict(
        target=args.get("email_domain") or username,
        output_file=output_file,
        emails_found=filtered_count if filtered_count is not None else emails_found,
        output_columns=["Email", "Repo", "GitHubUser", "Leaked", "LeakedSource", "CommitURL"],
    )
    if domain_filter is not None:
        result_fields["domain_filter"] = domain_filter
        result_fields["emails_after_filter"] = filtered_count

    return _ok("search_emails", t0, **result_fields)


async def tool_map_org_affiliations(args: dict) -> str:
    t0 = time.time()
    from rek_org_intel import OrgIntelRunner

    target      = args["target"]
    output_file = args.get("output_file", "org_intel_results.csv")

    runner = OrgIntelRunner(timeout=15, silent=True)

    loop = asyncio.get_running_loop()
    results = await loop.run_in_executor(
        None,
        lambda: runner.run(
            target=target,
            token=args.get("token"),
            max_members=args.get("max_members", 100),
            max_repos=args.get("max_repos", 30),
            output_file=output_file,
            scan_affiliated_count=args.get("scan_affiliated_count", 5),
        )
    )

    entity          = results.get("entity", {})
    bridge_members  = results.get("bridge_members", {})
    affiliated_orgs = results.get("affiliated_orgs", [])
    api_findings    = results.get("api_findings", [])

    spec_files    = [f for f in api_findings if f["type"] == "api_spec_file"]
    route_hits    = [f for f in api_findings if f["type"] == "route_definition"]
    cred_hits     = [f for f in api_findings if f["type"] == "api_credential"]
    all_endpoints = list({ep for f in spec_files for ep in f.get("endpoints", [])})

    base = os.path.splitext(output_file)[0]

    return _ok("map_org_affiliations", t0,
        target=target,
        entity_type=entity.get("type", "unknown"),
        public_repos=entity.get("public_repos"),
        members_scanned=results.get("members_scanned", 0),
        bridge_members_count=len(bridge_members),
        affiliated_orgs_count=len(affiliated_orgs),
        top_affiliated_orgs=[
            {"org": a["org"], "member_count": a["member_count"]}
            for a in affiliated_orgs[:10]
        ],
        bridge_members=[
            {"member": m, "orgs": orgs[:10]}
            for m, orgs in list(bridge_members.items())[:20]
        ],
        api_surface={
            "spec_files_found": len(spec_files),
            "route_definition_hits": len(route_hits),
            "credential_pattern_hits": len(cred_hits),
            "unique_endpoints": len(all_endpoints),
        },
        output_files={
            "affiliations": f"{base}_affiliations.csv",
            "bridge_members": f"{base}_bridge_members.json",
            "api_findings": f"{base}_api_findings.csv",
            "endpoints": f"{base}_endpoints.txt",
        },
    )


async def tool_run_playbook(args: dict) -> str:
    t0 = time.time()
    domain = args["domain"]
    version = args.get("version", "v1")
    threads = args.get("threads", 100)

    playbook_map = {
        "v1": "playbook/rek-playbook-v1.sh",
        "v2": "playbook/rek-playbook-v2.sh",
        "standard": "playbook/rek-playbook.sh"
    }
    playbook = playbook_map.get(version, "playbook/rek-playbook-v1.sh")
    playbook_path = os.path.join(_SERVER_DIR, playbook)

    if not os.path.exists(playbook_path):
        return _err("run_playbook", t0, f"Playbook not found: {playbook_path}",
                    target=domain, playbook_version=version)

    output_dir = args.get("output_dir")
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    cwd = output_dir if (output_dir and version != "v1") else _SERVER_DIR

    cmd = ["bash", playbook_path, "-d", domain, "-t", str(threads)]
    if args.get("chaos_key"):
        cmd += ["--chaos-key", args["chaos_key"]]
    if args.get("github_token"):
        cmd += ["--github-token", args["github_token"]]
    if args.get("skip_portscan"):
        cmd.append("--skip-portscan")
    if args.get("skip_jsanalysis"):
        cmd.append("--skip-jsanalysis")
    if output_dir and version == "v1":
        cmd += ["-o", output_dir]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3600)
        output = stdout.decode("utf-8", errors="replace")
        tail = output[-3000:] if len(output) > 3000 else output
        return _ok("run_playbook", t0,
            target=domain,
            playbook_version=version,
            exit_code=proc.returncode,
            output_dir=output_dir,
            raw_output_tail=tail,
        )
    except asyncio.TimeoutError:
        return _err("run_playbook", t0, "Playbook timed out after 1 hour",
                    target=domain, playbook_version=version)
    except Exception as e:
        return _err("run_playbook", t0, str(e),
                    target=domain, playbook_version=version)


async def tool_run_port_scan(args: dict) -> str:
    t0 = time.time()
    host       = args.get("host")
    hosts_file = args.get("hosts_file")
    ports      = args.get("ports", "80,443,3000,5000,8000,8001,8080,8081,8088,8443,8888,9000")
    output_file = args.get("output_file", "port_results.txt")

    if not host and not hosts_file:
        return _err("run_port_scan", t0, "Must provide either host or hosts_file")
    if hosts_file and not os.path.exists(hosts_file):
        return _err("run_port_scan", t0, f"hosts_file not found: {hosts_file}")

    # Domain gate + scope gate: check explicit host before issuing any TCP connections.
    if host:
        blocked = _domain_gate_check(host, "run_port_scan", t0)
        if blocked:
            return blocked
        blocked = _scope_check(host, "run_port_scan", t0)
        if blocked:
            return blocked

    cmd = [
        "naabu",
        "-p", ports,
        "-c", str(args.get("concurrency", 100)),
        "-timeout", str(args.get("timeout", 10)),
        "-silent",
    ]
    if host:
        cmd += ["-host", host]
    else:
        cmd += ["-l", hosts_file]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=_SERVER_DIR,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        output = stdout.decode("utf-8", errors="replace").strip()

        if proc.returncode != 0 and not output:
            err_msg = stderr.decode("utf-8", errors="replace").strip()
            return _err("run_port_scan", t0,
                        err_msg or f"naabu exited {proc.returncode}",
                        target=host or hosts_file)

        open_ports = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                h, p = line.rsplit(":", 1)
                open_ports.append({"host": h, "port": int(p) if p.isdigit() else p})
            else:
                open_ports.append({"host": line, "port": None})

        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(output)

        return _ok("run_port_scan", t0,
            target=host or hosts_file,
            ports_scanned=ports,
            open_ports_count=len(open_ports),
            open_ports=open_ports[:500],
            output_file=output_file,
        )
    except FileNotFoundError:
        return _err("run_port_scan", t0,
                    "naabu not found — install via playbook/install-script.sh",
                    target=host or hosts_file)
    except asyncio.TimeoutError:
        return _err("run_port_scan", t0, "Port scan timed out after 10 minutes",
                    target=host or hosts_file)
    except Exception as e:
        return _err("run_port_scan", t0, str(e), target=host or hosts_file)


async def tool_run_endpoint_scan(args: dict) -> str:
    t0 = time.time()
    url        = args.get("url")
    urls_file  = args.get("urls_file")
    scanner    = args.get("scanner", "katana")
    depth      = args.get("depth", 5)
    concurrency = args.get("concurrency", 50)
    timeout    = args.get("timeout", 10)
    output_file = args.get("output_file", "endpoint_results.txt")

    if not url and not urls_file:
        return _err("run_endpoint_scan", t0, "Must provide either url or urls_file")
    if urls_file and not os.path.exists(urls_file):
        return _err("run_endpoint_scan", t0, f"urls_file not found: {urls_file}")

    # Domain gate + scope gate: check explicit URL target before issuing any HTTP crawl.
    if url:
        blocked = _domain_gate_check(url, "run_endpoint_scan", t0)
        if blocked:
            return blocked
        blocked = _scope_check(url, "run_endpoint_scan", t0)
        if blocked:
            return blocked

    if scanner == "katana":
        cmd = [
            "katana",
            "-d", str(depth),
            "-c", str(concurrency),
            "-timeout", str(timeout),
            "-silent",
        ]
        if url:
            cmd += ["-u", url]
        else:
            cmd += ["-list", urls_file]
    else:  # gau
        cmd = [
            "gau",
            "--threads", str(concurrency),
            "--blacklist", "jpg,jpeg,png,gif,svg,css,woff,woff2,ttf,ico",
        ]
        if url:
            from urllib.parse import urlparse
            cmd.append(urlparse(url).netloc or url)
        else:
            # gau doesn't accept a file natively — read and pass domain list
            with open(urls_file, "r", encoding="utf-8") as fh:
                from urllib.parse import urlparse
                domains = list({urlparse(l.strip()).netloc for l in fh if l.strip()})
            cmd.extend(domains)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=_SERVER_DIR,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        output = stdout.decode("utf-8", errors="replace").strip()

        if proc.returncode != 0 and not output:
            err_msg = stderr.decode("utf-8", errors="replace").strip()
            return _err("run_endpoint_scan", t0,
                        err_msg or f"{scanner} exited {proc.returncode}",
                        target=url or urls_file, scanner=scanner)

        endpoints = [line.strip() for line in output.splitlines() if line.strip()]

        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(endpoints))

        return _ok("run_endpoint_scan", t0,
            target=url or urls_file,
            scanner=scanner,
            depth=depth if scanner == "katana" else None,
            endpoints_found=len(endpoints),
            endpoints=endpoints[:1000],
            output_file=output_file,
        )
    except FileNotFoundError:
        return _err("run_endpoint_scan", t0,
                    f"{scanner} not found — install via playbook/install-script.sh",
                    target=url or urls_file, scanner=scanner)
    except asyncio.TimeoutError:
        return _err("run_endpoint_scan", t0, "Endpoint scan timed out after 10 minutes",
                    target=url or urls_file, scanner=scanner)
    except Exception as e:
        return _err("run_endpoint_scan", t0, str(e), target=url or urls_file)


async def tool_query_target_state(args: dict) -> str:
    t0 = time.time()
    target = args["target"]
    snap   = _state.get_target_state(target)
    return _ok("query_target_state", t0,
        target=target,
        **snap,
    )


async def tool_query_subdomains(args: dict) -> str:
    t0 = time.time()
    target = args["target"]
    subs   = _state.get_known_subdomains(target)
    return _ok("query_subdomains", t0,
        target=target,
        count=len(subs),
        subdomains=subs,
    )


async def tool_query_services(args: dict) -> str:
    t0 = time.time()
    host  = args["host"]
    ports = _state.get_open_ports(host)
    endpoints = _state.get_endpoints(host)
    tech  = _state.get_technology_stack(host)
    return _ok("query_services", t0,
        host=host,
        open_ports=ports,
        open_ports_count=len(ports),
        endpoints=endpoints,
        endpoints_count=len(endpoints),
        technology_stack=tech,
    )


async def tool_run_incremental_recon(args: dict) -> str:
    t0 = time.time()
    target = args["target"]
    ports  = args.get("ports", "80,443,3000,5000,8000,8001,8080,8081,8088,8443,8888,9000")

    _state.upsert_target(target)
    known_before = set(_state.get_known_subdomains(target))

    # ------------------------------------------------------------------ #
    # Phase 1 — Subdomain enumeration                                     #
    # ------------------------------------------------------------------ #
    from rek import SubdomainScanner
    output_file = f"{target}_incremental.txt"
    scanner = SubdomainScanner(
        timeout=10,
        wordlist_path=args.get("wordlist_path"),
        concurrency=50,
        retries=3,
        silent=True,
    )
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        await scanner.enumerate_subdomains(
            domain=target,
            output_file=output_file,
            github_token=args.get("github_token"),
        )

    all_discovered = sorted(scanner.subdomains | scanner.validated_subdomains)
    new_subdomains = _state.get_new_subdomains(target, all_discovered)

    for sub in all_discovered:
        _state.upsert_subdomain(sub, target, "run_incremental_recon")

    # ------------------------------------------------------------------ #
    # Phase 2 — Port scan on new subdomains only                         #
    # ------------------------------------------------------------------ #
    new_services: list = []
    if new_subdomains and not args.get("skip_port_scan", False):
        for sub in new_subdomains:
            cmd = [
                "naabu",
                "-host", sub,
                "-p", ports,
                "-c", "100",
                "-timeout", "10",
                "-silent",
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=_SERVER_DIR,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                for line in stdout.decode("utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if ":" in line:
                        h, p = line.rsplit(":", 1)
                        if p.isdigit():
                            port_int = int(p)
                            if _state.upsert_service(h, port_int):
                                new_services.append({"host": h, "port": port_int})
            except (FileNotFoundError, asyncio.TimeoutError, Exception):
                pass

    # ------------------------------------------------------------------ #
    # Phase 3 — Endpoint scan on new web-facing services                 #
    # ------------------------------------------------------------------ #
    new_endpoints: list = []
    web_ports = {80, 443, 8000, 8001, 8080, 8081, 8088, 8443, 8888}
    if not args.get("skip_endpoint_scan", False):
        web_targets = [
            f"{'https' if svc['port'] in (443, 8443) else 'http'}://{svc['host']}:{svc['port']}"
            for svc in new_services
            if svc["port"] in web_ports
        ]
        for web_url in web_targets:
            cmd = [
                "katana",
                "-u", web_url,
                "-d", "3",
                "-c", "30",
                "-timeout", "10",
                "-silent",
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=_SERVER_DIR,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                for line in stdout.decode("utf-8", errors="replace").splitlines():
                    url = line.strip()
                    if url and _state.upsert_endpoint(url):
                        new_endpoints.append(url)
            except (FileNotFoundError, asyncio.TimeoutError, Exception):
                pass

    return _ok("run_incremental_recon", t0,
        target=target,
        known_subdomains_before=len(known_before),
        total_subdomains_after=len(known_before) + len(new_subdomains),
        new_subdomains_discovered=new_subdomains,
        new_subdomains_count=len(new_subdomains),
        new_services_discovered=new_services,
        new_services_count=len(new_services),
        new_endpoints_discovered=new_endpoints[:500],
        new_endpoints_count=len(new_endpoints),
        phases_skipped=[
            p for p, skip in [
                ("port_scan", args.get("skip_port_scan", False)),
                ("endpoint_scan", args.get("skip_endpoint_scan", False)),
            ] if skip
        ],
    )


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

async def tool_get_prioritized_findings(args: dict) -> str:
    t0 = time.time()
    from rek_intel import intel_engine
    target    = args["target"]
    min_score = args.get("min_score", 0)

    result = intel_engine.analyze_target(target)

    if min_score > 0:
        for tier in ("high_priority", "medium_priority", "low_priority"):
            result[tier] = [f for f in result[tier] if f["score"] >= min_score]

    return _ok("get_prioritized_findings", t0,
        target=target,
        hosts_analyzed=result["hosts_analyzed"],
        high_priority=result["high_priority"],
        medium_priority=result["medium_priority"],
        low_priority=result["low_priority"],
        scoring_metadata=result["scoring_metadata"],
        summary={
            "high_count":   len(result["high_priority"]),
            "medium_count": len(result["medium_priority"]),
            "low_count":    len(result["low_priority"]),
            "min_score_filter": min_score,
        },
    )


async def tool_get_top_targets(args: dict) -> str:
    t0 = time.time()
    from rek_intel import intel_engine
    target  = args["target"]
    limit   = args.get("limit", 10)
    findings = intel_engine.get_top_targets(target, limit)
    return _ok("get_top_targets", t0,
        target=target,
        limit=limit,
        count=len(findings),
        findings=findings,
    )


async def tool_expand_target(args: dict) -> str:
    t0 = time.time()
    from rek_expand import expansion_engine

    target  = args["target"]
    org     = args.get("org", "")
    sources = args.get("sources") or None  # None → expand_all uses ALL_SOURCES

    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: expansion_engine.expand_all(target, org, sources)
    )

    return _ok("expand_target", t0,
        target=target,
        sources_run=result["sources_run"],
        new_subdomains=result["new_subdomains"],
        new_infra_cidrs=result["new_infra_cidrs"],
        per_source=result["per_source"],
    )


async def tool_list_discovered_assets(args: dict) -> str:
    t0 = time.time()
    from rek_expand import expansion_engine

    target = args["target"]

    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: expansion_engine.list_discovered_assets(target)
    )

    return _ok("list_discovered_assets", t0,
        target=target,
        subdomains=result["subdomains"],
        services=result["services"],
        endpoints=result["endpoints"],
        technologies=result["technologies"],
        infrastructure=result["infrastructure"],
        stats=result["stats"],
    )


async def tool_schedule_target(args: dict) -> str:
    t0 = time.time()
    from rek_scheduler import ReconScheduler

    target = args["target"]
    mode   = args.get("mode", "standard")
    org    = args.get("org", "")

    sched = ReconScheduler(mode=mode)
    loop  = asyncio.get_running_loop()

    # review_queue_only: plan but don't enqueue
    enqueue = (mode != "review_queue_only")
    tasks   = await loop.run_in_executor(
        None, lambda: sched.plan(target, org=org, mode=mode, enqueue=enqueue)
    )

    return _ok("schedule_target", t0,
        target=target,
        mode=mode,
        enqueued=enqueue,
        tasks_planned=len(tasks),
        tasks=tasks,
    )


async def tool_run_scheduler(args: dict) -> str:
    t0 = time.time()
    from rek_scheduler import ReconScheduler

    target = args.get("target")
    limit  = int(args.get("limit", 10))
    mode   = args.get("mode", "standard")

    sched  = ReconScheduler(mode=mode)
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: sched.run(target, limit=limit, mode=mode)
    )

    return _ok("run_scheduler", t0,
        target=target or "all",
        mode=result["mode"],
        tasks_run=result["tasks_run"],
        tasks_failed=result["tasks_failed"],
        completed_ids=result["completed_ids"],
        failed_ids=result["failed_ids"],
    )


async def tool_get_scheduler_status(args: dict) -> str:
    t0 = time.time()
    from rek_scheduler import recon_scheduler

    summary = recon_scheduler.status()
    return _ok("get_scheduler_status", t0, **summary)


async def tool_get_target_plan(args: dict) -> str:
    t0 = time.time()
    from rek_scheduler import recon_scheduler

    target = args["target"]
    tasks  = recon_scheduler.queue(target)

    return _ok("get_target_plan", t0,
        target=target,
        pending_count=len(tasks),
        tasks=tasks,
    )


async def tool_run_false_positive_suppression(args: dict) -> str:
    t0 = time.time()
    from rek_suppression import suppression_engine

    target = args["target"]
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: suppression_engine.run_suppression(target)
    )

    return _ok("run_false_positive_suppression", t0,
        target=target,
        summary=result["summary"],
        audit=result["audit"],
    )


async def tool_list_suppressed_assets(args: dict) -> str:
    t0 = time.time()
    from rek_suppression import suppression_engine

    target = args["target"]
    result = suppression_engine.list_suppressed(target)

    return _ok("list_suppressed_assets", t0,
        target=target,
        counts=result["counts"],
        suppressed=result["suppressed"],
        deferred=result["deferred"],
        merged=result["merged"],
    )


async def tool_restore_asset(args: dict) -> str:
    t0 = time.time()
    from rek_suppression import suppression_engine

    asset  = args["asset"]
    result = suppression_engine.restore_asset(asset)

    if result["restored"]:
        return _ok("restore_asset", t0,
            fqdn=result["fqdn"],
            previous_status=result["previous_status"],
            current_status="candidate",
        )
    return _err("restore_asset", t0,
        result.get("error", "unknown error"),
        fqdn=asset,
    )


async def tool_get_pending_domains(args: dict) -> str:
    t0 = time.time()
    from rek_domain_gate import domain_gate

    summary  = domain_gate.get_summary()
    pending  = domain_gate.list_pending()
    approved = domain_gate.list_approved()
    rejected = domain_gate.list_rejected()

    return _ok("get_pending_domains", t0,
        summary=summary,
        pending=pending,
        approved=approved,
        rejected=rejected,
    )


async def tool_approve_domain(args: dict) -> str:
    t0 = time.time()
    from rek_domain_gate import domain_gate

    domain = args["domain"].strip().lower()
    result = domain_gate.approve_domain(domain)

    if result.get("approved"):
        return _ok("approve_domain", t0,
            domain=result["domain"],
            status="approved",
        )
    return _err("approve_domain", t0,
        result.get("error", "unknown error"),
        domain=domain,
    )


async def tool_reject_domain(args: dict) -> str:
    t0 = time.time()
    from rek_domain_gate import domain_gate

    domain = args["domain"].strip().lower()
    result = domain_gate.reject_domain(domain)

    if result.get("rejected"):
        return _ok("reject_domain", t0,
            domain=result["domain"],
            status="rejected",
        )
    return _err("reject_domain", t0,
        result.get("error", "unknown error"),
        domain=domain,
    )


async def tool_check_scope(args: dict) -> str:
    t0 = time.time()
    from rek_scope import scope_guard

    assets  = args.get("assets", [])
    results = [scope_guard.in_scope(a) for a in assets]

    blocked = [r for r in results if not r["allowed"]]
    allowed = [r for r in results if r["allowed"]]

    return _ok("check_scope", t0,
        total=len(results),
        allowed_count=len(allowed),
        blocked_count=len(blocked),
        results=results,
    )


async def tool_get_scope_config(args: dict) -> str:
    t0 = time.time()
    from rek_scope import scope_guard

    cfg = scope_guard.get_config()
    return _ok("get_scope_config", t0, **cfg)


HANDLERS = {
    "enumerate_subdomains":    tool_enumerate_subdomains,
    "check_http_status":       tool_check_http_status,
    "scan_directories":        tool_scan_directories,
    "search_emails":           tool_search_emails,
    "map_org_affiliations":    tool_map_org_affiliations,
    "run_playbook":            tool_run_playbook,
    "run_port_scan":           tool_run_port_scan,
    "run_endpoint_scan":       tool_run_endpoint_scan,
    "query_target_state":      tool_query_target_state,
    "query_subdomains":        tool_query_subdomains,
    "query_services":          tool_query_services,
    "run_incremental_recon":   tool_run_incremental_recon,
    "get_prioritized_findings": tool_get_prioritized_findings,
    "get_top_targets":         tool_get_top_targets,
    "expand_target":           tool_expand_target,
    "list_discovered_assets":  tool_list_discovered_assets,
    "schedule_target":         tool_schedule_target,
    "run_scheduler":                    tool_run_scheduler,
    "get_scheduler_status":             tool_get_scheduler_status,
    "get_target_plan":                  tool_get_target_plan,
    "run_false_positive_suppression":   tool_run_false_positive_suppression,
    "list_suppressed_assets":           tool_list_suppressed_assets,
    "restore_asset":                    tool_restore_asset,
    "check_scope":                      tool_check_scope,
    "get_scope_config":                 tool_get_scope_config,
    "get_pending_domains":              tool_get_pending_domains,
    "approve_domain":                   tool_approve_domain,
    "reject_domain":                    tool_reject_domain,
}

# ---------------------------------------------------------------------------
# Transport-agnostic request processor
# ---------------------------------------------------------------------------

SUPPORTED_VERSIONS = {"2024-11-05", "2025-03-26"}
DEFAULT_VERSION = "2024-11-05"


async def process_request(request: dict) -> dict | None:
    """Process one JSON-RPC 2.0 MCP request. Returns a response dict or None (notifications)."""
    req_id = request.get("id")
    method = request.get("method", "")
    params = request.get("params") or {}
    _log.debug(">> %s  id=%s", method, req_id)

    if method == "initialize":
        requested = params.get("protocolVersion", DEFAULT_VERSION)
        version = requested if requested in SUPPORTED_VERSIONS else DEFAULT_VERSION
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "rek_mcp_server", "version": "1.0.0"}
            }
        }

    elif method == "initialized":
        return None  # notification, no response

    elif method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS}
        }

    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or {}
        handler = HANDLERS.get(tool_name)

        if handler is None:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                    "isError": True
                }
            }

        try:
            _log.info("CALL %s  args=%s", tool_name, arguments)
            result_text = await handler(arguments)
            _log.info("DONE %s", tool_name)
            # Persist normalized entities to the recon state graph
            _update_state(tool_name, arguments, result_text)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": result_text}]
                }
            }
        except Exception as e:
            _log.exception("ERROR in tool %s: %s", tool_name, e)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Tool execution error: {e}"}],
                    "isError": True
                }
            }

    else:
        # Notifications (no id) are silently ignored
        if req_id is None:
            return None
        # Claude Desktop's validator rejects error-format responses;
        # return an empty result so the client isn't left waiting
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}


def _error_response(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


# ---------------------------------------------------------------------------
# StdIO transport
# ---------------------------------------------------------------------------

def _stdio_send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


async def _stdio_readline(loop: asyncio.AbstractEventLoop) -> str | None:
    return await loop.run_in_executor(None, sys.stdin.readline)


async def run_stdio() -> None:
    sys.stderr = _StderrToLog()  # capture all stderr into the log file
    _log.info("=== REK MCP Server started (StdIO) ===")
    loop = asyncio.get_running_loop()

    while True:
        try:
            line = await _stdio_readline(loop)
        except Exception:
            break

        if not line:
            break

        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            _log.warning("Parse error (line dropped): %s", e)
            continue

        try:
            response = await process_request(request)
            if response is not None:
                _stdio_send(response)
        except Exception as e:
            _log.exception("Unhandled error processing request: %s", e)


# ---------------------------------------------------------------------------
# HTTP transport — SSE (2024-11-05) + Streamable HTTP (2025-03-26)
# ---------------------------------------------------------------------------

def run_http(host: str, port: int) -> None:
    try:
        from fastapi import FastAPI, Request, Response
        from fastapi.responses import JSONResponse, StreamingResponse
        from sse_starlette.sse import EventSourceResponse
        import uvicorn
    except ImportError:
        _log.error("HTTP mode requires: pip install fastapi \"uvicorn[standard]\" sse-starlette")
        sys.exit(1)

    app = FastAPI(title="REK MCP Server")

    # session_id -> asyncio.Queue  (used by SSE transport)
    sse_sessions: dict[str, asyncio.Queue] = {}

    # ------------------------------------------------------------------ #
    # SSE transport  (MCP 2024-11-05)                                     #
    #   GET  /sse       — client subscribes; receives an `endpoint` event  #
    #   POST /messages  — client sends JSON-RPC; response arrives via SSE  #
    # ------------------------------------------------------------------ #

    @app.get("/sse")
    async def sse_connect(request: Request):
        session_id = str(uuid.uuid4())
        queue: asyncio.Queue = asyncio.Queue()
        sse_sessions[session_id] = queue

        async def generator():
            # Tell the client where to POST its messages
            yield {
                "event": "endpoint",
                "data": f"/messages?sessionId={session_id}"
            }
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        msg = await asyncio.wait_for(queue.get(), timeout=15)
                        yield {"data": json.dumps(msg)}
                    except asyncio.TimeoutError:
                        yield {"event": "ping", "data": ""}
            finally:
                sse_sessions.pop(session_id, None)

        return EventSourceResponse(generator())

    @app.post("/messages")
    async def sse_message(request: Request):
        session_id = request.query_params.get("sessionId", "")
        queue = sse_sessions.get(session_id)
        if queue is None:
            return Response(status_code=404, content="Session not found")

        try:
            body = await request.json()
        except Exception:
            return Response(status_code=400, content="Invalid JSON")

        try:
            response = await process_request(body)
            if response is not None:
                await queue.put(response)
        except Exception as e:
            _log.exception("SSE handler error: %s", e)
            await queue.put({
                "jsonrpc": "2.0", "id": body.get("id"),
                "result": {"content": [{"type": "text", "text": str(e)}], "isError": True}
            })

        return Response(status_code=202)

    # ------------------------------------------------------------------ #
    # Streamable HTTP transport  (MCP 2025-03-26)                         #
    #   POST /mcp — single endpoint for all JSON-RPC traffic              #
    #   Responds with JSON or SSE stream depending on Accept header        #
    # ------------------------------------------------------------------ #

    @app.post("/mcp")
    async def streamable_http(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content=_error_response(None, -32700, "Parse error")
            )

        wants_sse = "text/event-stream" in request.headers.get("accept", "")

        # Batch request
        if isinstance(body, list):
            responses = []
            for req in body:
                try:
                    resp = await process_request(req)
                    if resp is not None:
                        responses.append(resp)
                except Exception as e:
                    responses.append(_error_response(req.get("id"), -32603, str(e)))

            if wants_sse:
                async def batch_stream():
                    for r in responses:
                        yield f"data: {json.dumps(r)}\n\n"
                return StreamingResponse(batch_stream(), media_type="text/event-stream")
            return JSONResponse(content=responses)

        # Single request
        try:
            response = await process_request(body)
        except Exception as e:
            response = _error_response(body.get("id"), -32603, str(e))

        if response is None:
            return Response(status_code=202)  # notification acknowledged

        if wants_sse:
            async def single_stream():
                yield f"data: {json.dumps(response)}\n\n"
            return StreamingResponse(single_stream(), media_type="text/event-stream")

        return JSONResponse(content=response)

    _log.info("=== REK MCP Server started (HTTP) on %s:%s ===", host, port)
    _log.info("  SSE transport:             GET  http://%s:%s/sse", host, port)
    _log.info("  SSE messages:              POST http://%s:%s/messages", host, port)
    _log.info("  Streamable HTTP transport: POST http://%s:%s/mcp", host, port)
    uvicorn.run(app, host=host, port=port, log_level="warning")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="REK MCP Server")
    parser.add_argument(
        "--http", action="store_true",
        help="Run HTTP server (SSE + Streamable HTTP) instead of StdIO"
    )
    parser.add_argument(
        "--host", default="0.0.0.0",
        help="HTTP bind host (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=8000,
        help="HTTP port (default: 8000)"
    )
    args = parser.parse_args()

    if args.http:
        run_http(args.host, args.port)
    else:
        asyncio.run(run_stdio())
