#!/usr/bin/env python3
"""
rek_org_intel.py

Organizational affiliation mapping and API surface discovery for GitHub targets.

Phase 1 — Affiliation mapping:
  Resolves target entity (User or Org via GitHub API), enumerates members,
  maps cross-org memberships, and surfaces bridge members — individuals active
  in the target org AND one or more external orgs, representing potential
  proxy/supply-chain exposure vectors.

Phase 2 — API surface discovery:
  Walks repo file trees across the target and top affiliated orgs, flags API
  spec files (OpenAPI/Swagger/.env/config), parses discovered specs to extract
  endpoint lists, and searches code for route definitions and credential patterns.

Output files:
  <base>_affiliations.csv     — affiliated orgs ranked by shared member count
  <base>_bridge_members.json  — bridge member profiles with cross-org footprint
  <base>_api_findings.csv     — spec files, route definitions, credential flags
  <base>_endpoints.txt        — extracted API paths (feed into check_http_status)
"""

import csv
import json
import logging
import os
import re
import time
from collections import defaultdict
from typing import Dict, List, Optional

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_API_SPEC_FILENAMES = {
    "swagger.json", "swagger.yaml", "swagger.yml",
    "openapi.json", "openapi.yaml", "openapi.yml",
    "api.yaml", "api.yml", "api.json",
    ".env", ".env.local", ".env.production", ".env.staging",
    "config.yaml", "config.yml", "config.json",
    "secrets.yaml", "secrets.yml",
}

# GitHub code search terms — (label, query)
_CODE_SEARCH_TERMS = [
    ("route_definition",  "@app.route OR router.get OR @GetMapping OR router.post"),
    ("api_credential",    "api_key= OR api_secret= OR access_token= OR client_secret="),
]

# Endpoint extraction patterns for spec files
_JSON_PATH_RE = re.compile(r'"(/[^"]{1,200})"')
_YAML_PATH_RE = re.compile(r'^\s{0,4}(/\S+)\s*:', re.MULTILINE)

_FORMULA_CHARS = ("=", "+", "-", "@", "\t", "\r")


def _sanitize(value) -> str:
    """Neutralize spreadsheet formula injection."""
    s = str(value) if value is not None else ""
    return ("'" + s) if s.startswith(_FORMULA_CHARS) else s


# ---------------------------------------------------------------------------
# OrgAffiliationScanner
# ---------------------------------------------------------------------------

class OrgAffiliationScanner:
    """
    Maps cross-organizational affiliations from a GitHub target.
    Surfaces bridge members as potential proxy/supply-chain pivot points.
    """

    def __init__(self, timeout: int = 10, silent: bool = False):
        self.timeout = timeout
        self.silent  = silent
        self._log    = logging.getLogger(__name__)

    def _headers(self, token: Optional[str]) -> dict:
        h = {"Accept": "application/vnd.github.v3+json"}
        if token:
            h["Authorization"] = f"token {token}"
        return h

    def _get(self, url: str, token: Optional[str] = None) -> Optional[dict | list]:
        try:
            r = requests.get(url, headers=self._headers(token), timeout=self.timeout)
            self._check_rate_limit(r)
            return r.json() if r.status_code == 200 else None
        except requests.RequestException as e:
            self._log.debug("GET %s failed: %s", url, e)
            return None

    def _check_rate_limit(self, response: requests.Response) -> None:
        remaining = int(response.headers.get("X-RateLimit-Remaining", 10))
        if remaining < 5:
            reset_at = int(response.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(1, reset_at - int(time.time())) + 1
            if not self.silent:
                print(f"[!] Rate limit low ({remaining} remaining) — waiting {wait}s")
            time.sleep(wait)

    def resolve_entity(self, target: str, token: Optional[str] = None) -> dict:
        """Resolve target login to User or Organization via GitHub API."""
        data = self._get(f"https://api.github.com/users/{target}", token)
        if not data:
            return {"target": target, "type": "unknown"}
        return {
            "target":       target,
            "type":         data.get("type", "User"),  # "User" or "Organization"
            "name":         data.get("name"),
            "company":      data.get("company"),
            "email":        data.get("email"),
            "blog":         data.get("blog"),
            "location":     data.get("location"),
            "public_repos": data.get("public_repos", 0),
            "profile_url":  data.get("html_url"),
        }

    def get_org_members(self, org: str, token: Optional[str] = None) -> List[str]:
        """Enumerate public members of a GitHub organization (paginated)."""
        members, page = [], 1
        while True:
            data = self._get(
                f"https://api.github.com/orgs/{org}/members?per_page=100&page={page}",
                token,
            )
            if not data:
                break
            members.extend(m["login"] for m in data)
            if len(data) < 100:
                break
            page += 1
        return members

    def get_member_orgs(self, member: str, token: Optional[str] = None) -> List[str]:
        """Get public organization memberships for a GitHub user."""
        data = self._get(f"https://api.github.com/users/{member}/orgs", token)
        return [o["login"] for o in data] if data else []

    def map_affiliations(
        self,
        target:      str,
        token:       Optional[str] = None,
        max_members: int = 100,
    ) -> dict:
        """
        Build cross-org affiliation graph from target.

        For an Org target  — enumerates members, maps each member's other orgs.
        For a User target  — seeds from the user's own org memberships' members.

        Returns bridge members (in target + external orgs) and affiliated orgs
        ranked by shared member count (higher = stronger relationship = higher
        value as a proxy/supply-chain target).
        """
        entity = self.resolve_entity(target, token)

        if entity["type"] == "Organization":
            if not self.silent:
                print(f"[*] Enumerating members of org: {target}")
            seed_members = self.get_org_members(target, token)
        else:
            if not self.silent:
                print(f"[*] Resolving org memberships for user: {target}")
            user_orgs    = self.get_member_orgs(target, token)
            seed_members = [target]
            for org in user_orgs[:5]:
                seed_members.extend(self.get_org_members(org, token))

        seed_members = list(set(seed_members))[:max_members]

        if not self.silent:
            print(f"[*] Mapping cross-org affiliations for {len(seed_members)} members...")

        member_orgs: Dict[str, List[str]] = {}
        org_members: Dict[str, List[str]] = defaultdict(list)

        for member in seed_members:
            orgs = [o for o in self.get_member_orgs(member, token)
                    if o.lower() != target.lower()]
            member_orgs[member] = orgs
            for org in orgs:
                org_members[org].append(member)

        # Bridge members — active in the target AND at least one external org
        bridge_members = {m: orgs for m, orgs in member_orgs.items() if orgs}

        affiliated_orgs = sorted(
            [
                {
                    "org":            org,
                    "shared_members": mlist,
                    "member_count":   len(mlist),
                }
                for org, mlist in org_members.items()
            ],
            key=lambda x: x["member_count"],
            reverse=True,
        )

        return {
            "entity":          entity,
            "members_scanned": len(member_orgs),
            "bridge_members":  bridge_members,
            "affiliated_orgs": affiliated_orgs,
        }


# ---------------------------------------------------------------------------
# ApiSurfaceScanner
# ---------------------------------------------------------------------------

class ApiSurfaceScanner:
    """
    Discovers exposed API surfaces across GitHub organization repositories.

    Finds:
      - API spec files (OpenAPI/Swagger/.env/config) via repo tree traversal
      - Extracted endpoint lists parsed from discovered specs
      - Route definitions and credential pattern exposures via code search
    """

    def __init__(self, timeout: int = 10, silent: bool = False):
        self.timeout = timeout
        self.silent  = silent
        self._log    = logging.getLogger(__name__)

    def _headers(self, token: Optional[str]) -> dict:
        h = {"Accept": "application/vnd.github.v3+json"}
        if token:
            h["Authorization"] = f"token {token}"
        return h

    def _get(self, url: str, token: Optional[str] = None) -> Optional[dict | list]:
        try:
            r = requests.get(url, headers=self._headers(token), timeout=self.timeout)
            self._check_rate_limit(r)
            return r.json() if r.status_code == 200 else None
        except requests.RequestException as e:
            self._log.debug("GET %s failed: %s", url, e)
            return None

    def _get_raw(self, url: str, token: Optional[str] = None) -> Optional[str]:
        try:
            r = requests.get(url, headers=self._headers(token), timeout=self.timeout)
            return r.text if r.status_code == 200 else None
        except requests.RequestException:
            return None

    def _check_rate_limit(self, response: requests.Response) -> None:
        remaining = int(response.headers.get("X-RateLimit-Remaining", 10))
        if remaining < 5:
            reset_at = int(response.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(1, reset_at - int(time.time())) + 1
            if not self.silent:
                print(f"[!] Rate limit low ({remaining} remaining) — waiting {wait}s")
            time.sleep(wait)

    def get_org_repos(
        self, org: str, token: Optional[str] = None, max_repos: int = 30
    ) -> List[dict]:
        """Fetch repos for an org or user sorted by most recently updated."""
        data = self._get(
            f"https://api.github.com/orgs/{org}/repos?per_page={max_repos}&sort=updated",
            token,
        )
        if not data:
            data = self._get(
                f"https://api.github.com/users/{org}/repos?per_page={max_repos}&sort=updated",
                token,
            )
        return data or []

    def scan_repo_tree(
        self, org: str, repo: str, token: Optional[str] = None
    ) -> List[dict]:
        """Walk the full repo file tree and flag API-relevant files."""
        findings = []
        tree = self._get(
            f"https://api.github.com/repos/{org}/{repo}/git/trees/HEAD?recursive=1",
            token,
        )
        if not tree or "tree" not in tree:
            return findings

        repo_url = f"https://github.com/{org}/{repo}"
        for item in tree["tree"]:
            path     = item.get("path", "")
            filename = os.path.basename(path).lower()
            if filename not in _API_SPEC_FILENAMES:
                continue

            raw_url  = f"https://raw.githubusercontent.com/{org}/{repo}/HEAD/{path}"
            blob_url = f"{repo_url}/blob/HEAD/{path}"
            endpoints = self._extract_endpoints(raw_url, filename, token)

            findings.append({
                "type":      "api_spec_file",
                "org":       org,
                "repo":      repo,
                "path":      path,
                "url":       blob_url,
                "endpoints": endpoints,
            })

        return findings

    def _extract_endpoints(
        self, raw_url: str, filename: str, token: Optional[str] = None
    ) -> List[str]:
        """Parse an API spec file and extract path/endpoint list."""
        content = self._get_raw(raw_url, token)
        if not content:
            return []

        if filename.endswith(".json"):
            try:
                spec = json.loads(content)
                paths = spec.get("paths", {})
                if paths:
                    return list(paths.keys())[:100]
            except (json.JSONDecodeError, AttributeError):
                pass
            return _JSON_PATH_RE.findall(content)[:100]

        if filename.endswith((".yaml", ".yml")):
            return _YAML_PATH_RE.findall(content)[:100]

        return []

    def search_code_patterns(
        self, org: str, repo: str, token: Optional[str] = None
    ) -> List[dict]:
        """
        Search repo code for route definitions and credential exposures.
        Requires a token — GitHub code search is authenticated only.
        """
        if not token:
            return []

        findings = []
        for pattern_type, query in _CODE_SEARCH_TERMS:
            encoded = requests.utils.quote(f"{query} repo:{org}/{repo}")
            data = self._get(
                f"https://api.github.com/search/code?q={encoded}&per_page=10",
                token,
            )
            time.sleep(1)  # respect GitHub code search secondary rate limit
            if not data or not data.get("items"):
                continue
            for item in data["items"]:
                findings.append({
                    "type":      pattern_type,
                    "org":       org,
                    "repo":      repo,
                    "path":      item.get("path"),
                    "url":       item.get("html_url"),
                    "endpoints": [],
                })

        return findings

    def scan_org(
        self, org: str, token: Optional[str] = None, max_repos: int = 30
    ) -> List[dict]:
        """Full API surface scan across all repos in an org."""
        if not self.silent:
            print(f"  [>] API surface scan: {org}")

        repos    = self.get_org_repos(org, token, max_repos)
        findings = []
        for repo in repos:
            name      = repo["name"]
            findings += self.scan_repo_tree(org, name, token)
            findings += self.search_code_patterns(org, name, token)

        return findings


# ---------------------------------------------------------------------------
# OrgIntelRunner — orchestrator
# ---------------------------------------------------------------------------

class OrgIntelRunner:
    """
    Orchestrates affiliation mapping and API surface discovery into unified output.

    Attack surface logic:
      bridge member → affiliated org → weaker security posture
      → exposed API surface → credential/endpoint accessible without
        the primary target's hardening in the path.
    """

    def __init__(self, timeout: int = 10, silent: bool = False):
        self.affil_scanner = OrgAffiliationScanner(timeout=timeout, silent=silent)
        self.api_scanner   = ApiSurfaceScanner(timeout=timeout, silent=silent)
        self.silent        = silent

    def run(
        self,
        target:      str,
        token:       Optional[str] = None,
        max_members: int = 100,
        max_repos:   int = 30,
        output_file: str = "org_intel_results.csv",
    ) -> dict:
        """
        Full run:
          1. Resolve entity and map cross-org affiliations
          2. API surface scan across target + top 5 affiliated orgs
          3. Save structured output files
        """
        if not self.silent:
            print(f"\n[*] Starting org intel for: {target}")

        # Phase 1 — affiliation mapping
        affiliations     = self.affil_scanner.map_affiliations(target, token, max_members)
        bridge_count     = len(affiliations["bridge_members"])
        affiliated_count = len(affiliations["affiliated_orgs"])

        if not self.silent:
            print(f"[+] {bridge_count} bridge members across {affiliated_count} affiliated orgs")

        # Phase 2 — API surface scan on target + top affiliated orgs
        scan_targets = [target] + [
            a["org"] for a in affiliations["affiliated_orgs"][:5]
        ]
        all_api_findings = []
        for scan_target in scan_targets:
            all_api_findings.extend(
                self.api_scanner.scan_org(scan_target, token, max_repos)
            )

        affiliations["api_findings"] = all_api_findings

        # Save output
        self._save(affiliations, output_file)

        return affiliations

    def _save(self, results: dict, output_file: str) -> None:
        base = os.path.splitext(os.path.abspath(output_file))[0]
        os.makedirs(os.path.dirname(base), exist_ok=True)

        # 1. Affiliations CSV
        affil_path = f"{base}_affiliations.csv"
        with open(affil_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["AffiliatedOrg", "SharedMemberCount", "SharedMembers"])
            for a in results["affiliated_orgs"]:
                w.writerow([
                    _sanitize(a["org"]),
                    a["member_count"],
                    _sanitize("|".join(a["shared_members"])),
                ])

        # 2. Bridge members JSON (richest data — keep as JSON)
        bridge_path = f"{base}_bridge_members.json"
        with open(bridge_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "entity":         results["entity"],
                    "bridge_members": results["bridge_members"],
                },
                f,
                indent=2,
            )

        # 3. API findings CSV
        api_path = f"{base}_api_findings.csv"
        with open(api_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Type", "Org", "Repo", "Path", "URL", "EndpointCount"])
            for finding in results["api_findings"]:
                w.writerow([
                    _sanitize(finding.get("type")),
                    _sanitize(finding.get("org")),
                    _sanitize(finding.get("repo")),
                    _sanitize(finding.get("path")),
                    _sanitize(finding.get("url")),
                    len(finding.get("endpoints", [])),
                ])

        # 4. Flat endpoint list — feed directly into check_http_status
        endpoints_path = f"{base}_endpoints.txt"
        seen = set()
        with open(endpoints_path, "w", encoding="utf-8") as f:
            for finding in results["api_findings"]:
                for ep in finding.get("endpoints", []):
                    if ep not in seen:
                        f.write(ep + "\n")
                        seen.add(ep)

        if not self.silent:
            print(f"[+] Affiliations   -> {affil_path}")
            print(f"[+] Bridge members -> {bridge_path}")
            print(f"[+] API findings   -> {api_path}")
            print(f"[+] Endpoints      -> {endpoints_path} ({len(seen)} unique)")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="GitHub org affiliation mapping and API surface discovery"
    )
    parser.add_argument("target",            help="GitHub username or organization login")
    parser.add_argument("--token",           help="GitHub Personal Access Token")
    parser.add_argument("--max-members",     type=int, default=100,
                        help="Max members to map (default: 100)")
    parser.add_argument("--max-repos",       type=int, default=30,
                        help="Max repos to scan per org (default: 30)")
    parser.add_argument("--output",          default="org_intel_results.csv",
                        help="Output file base path (default: org_intel_results.csv)")
    parser.add_argument("--silent",          action="store_true")
    args = parser.parse_args()

    runner = OrgIntelRunner(timeout=15, silent=args.silent)
    runner.run(
        target=args.target,
        token=args.token,
        max_members=args.max_members,
        max_repos=args.max_repos,
        output_file=args.output,
    )


if __name__ == "__main__":
    main()
