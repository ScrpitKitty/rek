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
from typing import Any

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


# Redirect sys.stderr to the log file so nothing leaks to the StdIO stream
class _StderrToLog:
    def write(self, msg: str) -> None:
        msg = msg.strip()
        if msg:
            _log.warning("[stderr] %s", msg)

    def flush(self) -> None:
        pass

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
    }
]

# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

async def tool_enumerate_subdomains(args: dict) -> str:
    from rek import SubdomainScanner

    domain = args["domain"]
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

    lines = [
        f"Subdomain enumeration complete for: {domain}",
        f"Total discovered (unvalidated): {len(all_subs)}",
        f"DNS-validated: {len(validated)}",
        f"Output saved to: {output_file}",
        "",
    ]

    if validated:
        lines.append("DNS-Validated Subdomains:")
        lines.extend(f"  {s}" for s in validated)
    elif all_subs:
        lines.append(f"Discovered Subdomains (first 100):")
        lines.extend(f"  {s}" for s in all_subs[:100])
        if len(all_subs) > 100:
            lines.append(f"  ... and {len(all_subs) - 100} more (see {output_file})")

    return "\n".join(lines)


async def tool_check_http_status(args: dict) -> str:
    from rek import HTTPStatusChecker

    input_file = args["input_file"]
    output_file = args.get("output_file", "http_results.csv")

    checker = HTTPStatusChecker(
        timeout=args.get("timeout", 10),
        max_concurrent=args.get("concurrency", 100),
        silent=True
    )

    if not os.path.exists(input_file):
        return f"Error: input file not found: {input_file}"

    with open(input_file, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        return "No URLs found in input file."

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        await checker.check_all_urls(urls, output_file)

    return (
        f"HTTP status check complete.\n"
        f"Input:  {input_file}\n"
        f"Output: {output_file}\n"
        f"Results written in CSV format with columns: Subdomain, URL, Status Code, Title, Server, Error"
    )


async def tool_scan_directories(args: dict) -> str:
    from rek import DirectoryScanner

    scanner = DirectoryScanner(
        timeout=args.get("timeout", 10),
        max_concurrent=args.get("concurrency", 50),
        max_depth=args.get("depth", 5),
        silent=True
    )

    input_file = args.get("input_file")
    url = args.get("url")
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
        return "Error: must provide either a url or an input_file with status_codes."

    if not urls:
        return "No URLs to scan."

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

    lines = [
        "Directory scan complete.",
        f"Scanned {len(scanner.results)} target(s).",
    ]
    if extensions_filter:
        lines.append(f"Extension filter: {', '.join('.' + e for e in extensions_filter)}")
    lines.append("")

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
        lines.append(f"{target_url}: {len(hits)} paths found")
        for f in hits[:20]:
            lines.append(f"  [{f['status_code']}] {f['url']}")
        if len(hits) > 20:
            lines.append(f"  ... and {len(hits) - 20} more (see results/<domain>/dirs.csv)")

    return "\n".join(lines)


async def tool_search_emails(args: dict) -> str:
    from rek_email_search import EmailSearcher

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
        import csv as _csv
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

    summary = (
        f"Email search complete.\n"
        f"Output saved to: {output_file}\n"
        f"CSV columns: Email, Repo, GitHubUser, Leaked, LeakedSource, CommitURL"
    )
    if filtered_count is not None:
        summary += f"\nDomain filter '{domain_filter}' applied — {filtered_count} email(s) retained."
    return summary


async def tool_map_org_affiliations(args: dict) -> str:
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

    spec_files  = [f for f in api_findings if f["type"] == "api_spec_file"]
    route_hits  = [f for f in api_findings if f["type"] == "route_definition"]
    cred_hits   = [f for f in api_findings if f["type"] == "api_credential"]
    all_endpoints = list({
        ep
        for f in spec_files
        for ep in f.get("endpoints", [])
    })

    base = os.path.splitext(output_file)[0]

    lines = [
        f"Org intel complete for: {target}",
        f"Entity type: {entity.get('type', 'unknown')}",
        f"Public repos: {entity.get('public_repos', 'n/a')}",
        "",
        f"Affiliation mapping:",
        f"  Members scanned:   {results.get('members_scanned', 0)}",
        f"  Bridge members:    {len(bridge_members)}",
        f"  Affiliated orgs:   {len(affiliated_orgs)}",
        "",
    ]

    if affiliated_orgs:
        lines.append("Top affiliated orgs (by shared member count):")
        for a in affiliated_orgs[:10]:
            lines.append(f"  {a['org']:30s}  {a['member_count']} shared member(s)")

    if bridge_members:
        lines.append("")
        lines.append(f"Bridge members (pivot candidates):")
        for member, orgs in list(bridge_members.items())[:10]:
            lines.append(f"  {member:25s}  -> {', '.join(orgs[:5])}")

    lines += [
        "",
        f"API surface discovery:",
        f"  Spec files found:        {len(spec_files)}",
        f"  Route definition hits:   {len(route_hits)}",
        f"  Credential pattern hits: {len(cred_hits)}",
        f"  Unique endpoints parsed: {len(all_endpoints)}",
        "",
    ]

    if spec_files:
        lines.append("API spec files:")
        for f in spec_files[:15]:
            ep_count = len(f.get("endpoints", []))
            lines.append(f"  [{ep_count} endpoints] {f['org']}/{f['repo']} — {f['path']}")
            lines.append(f"    {f['url']}")

    lines += [
        "",
        f"Output files:",
        f"  {base}_affiliations.csv",
        f"  {base}_bridge_members.json",
        f"  {base}_api_findings.csv",
        f"  {base}_endpoints.txt  ({len(all_endpoints)} unique endpoints — feed into check_http_status)",
    ]

    return "\n".join(lines)


async def tool_run_playbook(args: dict) -> str:
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
        return f"Error: Playbook not found at {playbook_path}"

    output_dir = args.get("output_dir")
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    cwd = output_dir or _SERVER_DIR

    cmd = ["bash", playbook_path, "-d", domain, "-t", str(threads)]
    if args.get("chaos_key"):
        cmd += ["--chaos-key", args["chaos_key"]]
    if args.get("github_token"):
        cmd += ["--github-token", args["github_token"]]
    if args.get("skip_portscan"):
        cmd.append("--skip-portscan")
    if args.get("skip_jsanalysis"):
        cmd.append("--skip-jsanalysis")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3600)
        output = stdout.decode("utf-8", errors="replace")
        tail = output[-5000:] if len(output) > 5000 else output
        return (
            f"Playbook '{version}' finished for {domain} (exit code {proc.returncode}).\n\n"
            f"--- Output (last 5000 chars) ---\n{tail}"
        )
    except asyncio.TimeoutError:
        return f"Playbook timed out after 1 hour for {domain}."
    except Exception as e:
        return f"Error running playbook: {e}"


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

HANDLERS = {
    "enumerate_subdomains":  tool_enumerate_subdomains,
    "check_http_status":     tool_check_http_status,
    "scan_directories":      tool_scan_directories,
    "search_emails":         tool_search_emails,
    "map_org_affiliations":  tool_map_org_affiliations,
    "run_playbook":          tool_run_playbook,
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
