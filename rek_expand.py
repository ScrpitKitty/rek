#!/usr/bin/env python3
"""
rek_expand.py

Passive target expansion engine.

Discovers new subdomains and infrastructure from public passive sources
without sending any active probes to the target:

  - crt.sh         — certificate transparency log JSON API
  - TLS SAN        — SAN extraction from live TLS handshakes (stdlib ssl)
  - BGPView        — ASN lookup + prefix enumeration for org/IP
  - HackerTarget   — passive DNS API
  - ThreatMiner    — passive DNS API

All results are normalised and written directly into the state graph.
Deduplication is handled by ReconStateGraph — duplicate upserts are no-ops.

CLI usage
---------
  python rek_expand.py expand <target>                     # all sources
  python rek_expand.py expand <target> --org "Acme Inc"   # include ASN lookup
  python rek_expand.py expand <target> --sources ct san   # specific sources
  python rek_expand.py expand <target> --json             # raw JSON output
  python rek_expand.py assets <target>                     # list discovered assets
  python rek_expand.py assets <target> --json              # raw JSON output
"""

import argparse
import json
import logging
import logging.handlers
import os
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _MODULE_DIR)

_LOG_PATH = os.path.join(_MODULE_DIR, "logs", "recon_expand.log")

# ---------------------------------------------------------------------------
# Logger — isolated, never reaches root or stdout
# ---------------------------------------------------------------------------

_elog = logging.getLogger("rek_expand")
_elog.setLevel(logging.INFO)
_elog.propagate = False

os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)
_efh = logging.handlers.RotatingFileHandler(
    _LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_efh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_elog.addHandler(_efh)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CRTSH_URL      = "https://crt.sh/?q={domain}&output=json"
_BGPVIEW_SEARCH = "https://api.bgpview.io/search?query_term={query}"
_BGPVIEW_ASN    = "https://api.bgpview.io/asn/{asn}/prefixes"
_HT_DNS_URL     = "https://api.hackertarget.com/hostsearch/?q={domain}"
_TM_DNS_URL     = "https://api.threatminer.org/v2/domain.php?q={domain}&rt=2"

_HTTP_TIMEOUT   = 15  # seconds
_SAN_TIMEOUT    = 8   # seconds per host for TLS handshake
_SAN_WORKERS    = 20  # concurrent TLS threads

ALL_SOURCES     = ["ct", "san", "asn", "hackertarget", "threatminer"]


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _get_json(url: str, timeout: int = _HTTP_TIMEOUT) -> Optional[dict]:
    """Fetch URL and parse JSON. Returns None on any error."""
    try:
        req = Request(url, headers={"User-Agent": "rek-expand/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw)
    except Exception as exc:
        _elog.debug("HTTP error url=%s exc=%s", url, exc)
        return None


def _get_text(url: str, timeout: int = _HTTP_TIMEOUT) -> Optional[str]:
    """Fetch URL and return raw text. Returns None on any error."""
    try:
        req = Request(url, headers={"User-Agent": "rek-expand/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        _elog.debug("HTTP error url=%s exc=%s", url, exc)
        return None


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _clean_fqdn(name: str, parent: str) -> Optional[str]:
    """
    Normalise a raw name from CT/passive-DNS records.

    Strips wildcards, lowercases, verifies the name is a sub-label of
    parent, and rejects obvious artefacts (IP addresses, empty strings).
    """
    if not name:
        return None
    name = name.lower().strip().lstrip("*.")
    if not name or name == parent:
        return None
    # Must end with the parent domain
    if not (name.endswith("." + parent) or name == parent):
        return None
    # Reject if it looks like an IP address
    parts = name.split(".")
    if all(p.isdigit() for p in parts):
        return None
    return name


# ---------------------------------------------------------------------------
# Expansion engine
# ---------------------------------------------------------------------------

class TargetExpansionEngine:
    """
    Passive expansion across five intelligence sources.

    All methods return a list of discovered FQDNs (for DNS sources) or a
    summary dict (for ASN/infrastructure). The orchestrator (expand_all)
    normalises results and writes them to the state graph.
    """

    # ------------------------------------------------------------------ #
    # Source 1: crt.sh certificate transparency                           #
    # ------------------------------------------------------------------ #

    def expand_ct(self, domain: str) -> List[str]:
        """
        Query crt.sh for certificates containing domain.

        Returns deduplicated list of valid sub-FQDNs.
        """
        url  = _CRTSH_URL.format(domain=domain)
        data = _get_json(url)
        if not data:
            _elog.warning("CT_EMPTY domain=%s", domain)
            return []

        seen: set = set()
        results: List[str] = []
        for entry in data:
            # name_value may contain newline-separated SANs
            for raw in entry.get("name_value", "").split("\n"):
                fqdn = _clean_fqdn(raw, domain)
                if fqdn and fqdn not in seen:
                    seen.add(fqdn)
                    results.append(fqdn)

        _elog.info("CT_FOUND domain=%s count=%d", domain, len(results))
        return results

    # ------------------------------------------------------------------ #
    # Source 2: TLS SAN extraction                                        #
    # ------------------------------------------------------------------ #

    def _san_for_host(self, host: str, domain: str) -> List[str]:
        """Perform a TLS handshake to host:443 and extract SANs."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        try:
            with socket.create_connection((host, 443), timeout=_SAN_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            sans = []
            for type_, value in cert.get("subjectAltName", []):
                if type_ == "DNS":
                    fqdn = _clean_fqdn(value, domain)
                    if fqdn:
                        sans.append(fqdn)
            return sans
        except Exception:
            return []

    def expand_san(self, domain: str, known_hosts: Optional[List[str]] = None) -> List[str]:
        """
        Attempt TLS SAN extraction across all known hosts for domain.

        `known_hosts` defaults to [domain] if not provided. The state graph
        is not consulted here — the caller is responsible for supplying the
        host list so this method stays stateless and testable.
        """
        hosts   = known_hosts or [domain]
        seen:   set        = set()
        results: List[str] = []

        with ThreadPoolExecutor(max_workers=_SAN_WORKERS) as pool:
            futures = {pool.submit(self._san_for_host, h, domain): h for h in hosts}
            for fut in as_completed(futures):
                for fqdn in fut.result():
                    if fqdn not in seen:
                        seen.add(fqdn)
                        results.append(fqdn)

        _elog.info("SAN_FOUND domain=%s hosts_probed=%d count=%d",
                   domain, len(hosts), len(results))
        return results

    # ------------------------------------------------------------------ #
    # Source 3: BGPView ASN + prefix discovery                            #
    # ------------------------------------------------------------------ #

    def expand_asn(self, target: str, org_name: str = "") -> List[dict]:
        """
        Look up ASN(s) for org_name (or the resolved IP of target if no org)
        and return all announced CIDRs.

        Returns list of dicts: {asn, asn_name, cidr, ip_version}.
        """
        query = org_name.strip() if org_name.strip() else target
        data  = _get_json(_BGPVIEW_SEARCH.format(query=query))
        if not data or data.get("status") != "ok":
            _elog.warning("ASN_SEARCH_EMPTY query=%s", query)
            return []

        asns: List[int] = []
        for asn_rec in data.get("data", {}).get("asns", []):
            asn_num = asn_rec.get("asn")
            if asn_num:
                asns.append(asn_num)

        if not asns:
            _elog.warning("ASN_NO_RESULTS query=%s", query)
            return []

        cidrs: List[dict] = []
        for asn in asns[:5]:  # cap at 5 ASNs to avoid runaway API calls
            prefixes = _get_json(_BGPVIEW_ASN.format(asn=asn))
            if not prefixes or prefixes.get("status") != "ok":
                continue
            pdata = prefixes.get("data", {})
            for version, key in ((4, "ipv4_prefixes"), (6, "ipv6_prefixes")):
                for p in pdata.get(key, []):
                    prefix = p.get("prefix")
                    if prefix:
                        cidrs.append({
                            "asn":        str(asn),
                            "asn_name":   p.get("name", ""),
                            "cidr":       prefix,
                            "ip_version": version,
                        })

        _elog.info("ASN_FOUND query=%s asns=%s cidrs=%d", query, asns, len(cidrs))
        return cidrs

    # ------------------------------------------------------------------ #
    # Source 4 & 5: Passive DNS (HackerTarget + ThreatMiner)             #
    # ------------------------------------------------------------------ #

    def expand_hackertarget(self, domain: str) -> List[str]:
        """Query HackerTarget hostsearch passive DNS."""
        text = _get_text(_HT_DNS_URL.format(domain=domain))
        if not text or "error" in text.lower()[:50]:
            _elog.warning("HT_EMPTY domain=%s", domain)
            return []

        seen:    set        = set()
        results: List[str] = []
        for line in text.splitlines():
            parts = line.split(",")
            if len(parts) >= 1:
                fqdn = _clean_fqdn(parts[0].strip(), domain)
                if fqdn and fqdn not in seen:
                    seen.add(fqdn)
                    results.append(fqdn)

        _elog.info("HT_FOUND domain=%s count=%d", domain, len(results))
        return results

    def expand_threatminer(self, domain: str) -> List[str]:
        """Query ThreatMiner passive DNS."""
        data = _get_json(_TM_DNS_URL.format(domain=domain))
        if not data or data.get("status_code") != "200":
            _elog.warning("TM_EMPTY domain=%s", domain)
            return []

        seen:    set        = set()
        results: List[str] = []
        for entry in data.get("results", []):
            fqdn = _clean_fqdn(str(entry), domain)
            if fqdn and fqdn not in seen:
                seen.add(fqdn)
                results.append(fqdn)

        _elog.info("TM_FOUND domain=%s count=%d", domain, len(results))
        return results

    # ------------------------------------------------------------------ #
    # Orchestrator                                                         #
    # ------------------------------------------------------------------ #

    def expand_all(
        self,
        target: str,
        org: str = "",
        sources: Optional[List[str]] = None,
    ) -> dict:
        """
        Run all (or selected) passive expansion sources for target.

        Writes new FQDNs and infrastructure CIDRs directly into the state
        graph. Returns a summary dict with per-source counts and totals.
        """
        from rek_state import state_graph

        if sources is None:
            sources = ALL_SOURCES

        sources_lower = [s.lower() for s in sources]

        _elog.info("EXPAND_ALL_STARTED target=%s sources=%s", target, sources_lower)
        t0 = time.time()

        # Ensure target is registered
        state_graph.upsert_target(target)

        summary: Dict[str, int] = {s: 0 for s in sources_lower}
        new_subdomains = 0
        new_infra      = 0

        # Helper: write a list of FQDNs to state and count new ones
        def _ingest_fqdns(fqdns: List[str], source: str) -> int:
            nonlocal new_subdomains
            count = 0
            for fqdn in fqdns:
                added = state_graph.upsert_subdomain(fqdn, target, source_tool=source)
                if added:
                    new_subdomains += 1
                    count += 1
            return count

        # Collect known hosts for SAN probing (before adding new ones)
        known_hosts = [target] + state_graph.get_known_subdomains(target)

        if "ct" in sources_lower:
            fqdns = self.expand_ct(target)
            summary["ct"] = _ingest_fqdns(fqdns, "crt.sh")

        if "san" in sources_lower:
            fqdns = self.expand_san(target, known_hosts)
            summary["san"] = _ingest_fqdns(fqdns, "tls_san")

        if "asn" in sources_lower:
            cidrs = self.expand_asn(target, org)
            for cidr_rec in cidrs:
                added = state_graph.upsert_infrastructure(
                    target=target,
                    cidr=cidr_rec["cidr"],
                    asn=cidr_rec["asn"],
                    owner=cidr_rec["asn_name"],
                )
                if added:
                    new_infra += 1
            summary["asn"] = new_infra

        if "hackertarget" in sources_lower:
            fqdns = self.expand_hackertarget(target)
            summary["hackertarget"] = _ingest_fqdns(fqdns, "hackertarget")

        if "threatminer" in sources_lower:
            fqdns = self.expand_threatminer(target)
            summary["threatminer"] = _ingest_fqdns(fqdns, "threatminer")

        elapsed = round(time.time() - t0, 3)
        _elog.info(
            "EXPAND_ALL_COMPLETED target=%s new_subdomains=%d new_infra=%d elapsed=%.3fs",
            target, new_subdomains, new_infra, elapsed,
        )

        return {
            "target":           target,
            "sources_run":      sources_lower,
            "new_subdomains":   new_subdomains,
            "new_infra_cidrs":  new_infra,
            "per_source":       summary,
            "execution_time_seconds": elapsed,
        }

    # ------------------------------------------------------------------ #
    # Asset listing                                                        #
    # ------------------------------------------------------------------ #

    def list_discovered_assets(self, target: str) -> dict:
        """Return all assets stored in the state graph for target."""
        from rek_state import state_graph

        snap   = state_graph.get_target_state(target)
        infra  = state_graph.get_infrastructure(target)
        summary = state_graph.get_summary()

        return {
            "target":         target,
            "subdomains":     [s["fqdn"] for s in snap.get("subdomains", [])],
            "services":       snap.get("services", []),
            "endpoints":      [e["url"] for e in snap.get("endpoints", [])],
            "technologies":   snap.get("technologies", {}),
            "infrastructure": infra,
            "stats": {
                **snap.get("stats", {}),
                "infrastructure_cidrs": len(infra),
                "total_entities":       summary,
            },
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

expansion_engine = TargetExpansionEngine()

# ---------------------------------------------------------------------------
# CLI formatting helpers
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_CYAN  = "\033[96m"
_BOLD  = "\033[1m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if sys.stdout.isatty() else text


def _print_expand(result: dict) -> None:
    print()
    print(_c(f"REK Target Expansion — {result['target']}", _BOLD + _CYAN))
    print(f"  Sources run    : {', '.join(result['sources_run'])}")
    print(f"  New subdomains : {result['new_subdomains']}")
    print(f"  New CIDR blocks: {result['new_infra_cidrs']}")
    print()
    print("  Per-source breakdown:")
    for src, count in result["per_source"].items():
        print(f"    {src:15s}  {count} new")
    print()
    print(f"  Completed in {result['execution_time_seconds']}s")
    print()


def _print_assets(result: dict) -> None:
    target = result["target"]
    print()
    print(_c(f"REK Discovered Assets — {target}", _BOLD + _CYAN))

    subs = result["subdomains"]
    print(_c(f"\n  Subdomains ({len(subs)})", _GREEN))
    for s in subs:
        print(f"    {s}")

    infra = result["infrastructure"]
    print(_c(f"\n  Infrastructure CIDRs ({len(infra)})", _YELLOW))
    for r in infra:
        owner = f"  [{r['asn']}] {r['owner']}" if r.get("asn") else ""
        print(f"    {r['cidr']}{owner}")

    svcs = result["services"]
    print(_c(f"\n  Services ({len(svcs)})", _CYAN))
    for s in svcs:
        print(f"    {s['host']}:{s['port']}/{s['protocol']}")

    eps = result["endpoints"]
    print(_c(f"\n  Endpoints ({len(eps)})", _CYAN))
    for e in eps[:20]:
        print(f"    {e}")
    if len(eps) > 20:
        print(f"    ... and {len(eps) - 20} more")

    stats = result.get("stats", {})
    print()
    print(f"  State graph totals: {stats.get('total_entities', {})}")
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="rek_expand",
        description="REK Passive Target Expansion Engine",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_expand = sub.add_parser("expand", help="Run passive expansion for a target")
    p_expand.add_argument("target", help="Target domain (e.g., example.com)")
    p_expand.add_argument("--org", default="",
                          help="Organisation name for ASN lookup (optional)")
    p_expand.add_argument("--sources", nargs="+", default=ALL_SOURCES,
                          choices=ALL_SOURCES, metavar="SOURCE",
                          help=f"Sources to run (default: all). Choices: {ALL_SOURCES}")
    p_expand.add_argument("--json", action="store_true", dest="raw_json",
                          help="Output raw JSON instead of formatted report")

    p_assets = sub.add_parser("assets", help="List all discovered assets for a target")
    p_assets.add_argument("target", help="Target domain (e.g., example.com)")
    p_assets.add_argument("--json", action="store_true", dest="raw_json",
                          help="Output raw JSON instead of formatted list")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "expand":
        result = expansion_engine.expand_all(args.target, args.org, args.sources)
        if args.raw_json:
            print(json.dumps(result, indent=2))
        else:
            _print_expand(result)

    elif args.command == "assets":
        result = expansion_engine.list_discovered_assets(args.target)
        if args.raw_json:
            print(json.dumps(result, indent=2))
        else:
            _print_assets(result)


if __name__ == "__main__":
    main()
