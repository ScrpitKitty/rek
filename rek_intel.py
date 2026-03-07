#!/usr/bin/env python3
"""
rek_intel.py

Deterministic finding prioritization and anomaly detection engine.

Analyzes recon state graph data and ranks assets by investigative interest
using rule-based additive scoring — no AI or external dependencies required.

Scoring rules
-------------
  subdomain_keywords   : +5 per matching keyword found in hostname label segments
  suspicious_ports     : +4 per port matching the suspicious set
  sensitive_endpoints  : +5 per endpoint pattern matched (deduplicated per host)
  exposed_services     : +4 per known exposed service in tech stack (deduped)

Priority thresholds
-------------------
  high   : score >= 10
  medium : score >= 5
  low    : score <  5

CLI usage
---------
  python rek_intel.py analyze <target>          # full prioritized analysis
  python rek_intel.py analyze <target> --json   # raw JSON output
  python rek_intel.py top <target>              # top 10 findings
  python rek_intel.py top <target> --limit 20   # top N findings
  python rek_intel.py top <target> --json       # raw JSON output
"""

import argparse
import json
import logging
import logging.handlers
import os
import sys
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _MODULE_DIR)

_LOG_PATH = os.path.join(_MODULE_DIR, "logs", "recon_intelligence.log")

# ---------------------------------------------------------------------------
# Logger — isolated, never reaches root or stdout
# ---------------------------------------------------------------------------

_ilog = logging.getLogger("rek_intel")
_ilog.setLevel(logging.INFO)
_ilog.propagate = False

os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)
_ifh = logging.handlers.RotatingFileHandler(
    _LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_ifh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_ilog.addHandler(_ifh)

# ---------------------------------------------------------------------------
# Scoring rule constants
# ---------------------------------------------------------------------------

_SUBDOMAIN_KEYWORDS    = frozenset({
    "admin", "internal", "dev", "staging", "beta",
    "debug", "test", "backup", "old",
})
_SUBDOMAIN_KW_SCORE    = 5

_SUSPICIOUS_PORTS      = frozenset({3000, 5000, 5601, 6379, 8081, 9000, 9200, 2375})
_SUSPICIOUS_PORT_SCORE = 4

_SENSITIVE_PATHS       = frozenset({
    "/admin", "/debug", "/.git", "/config",
    "/graphql", "/internal", "/api/internal",
})
_SENSITIVE_PATH_SCORE  = 5

_EXPOSED_SERVICES      = frozenset({
    "jenkins", "grafana", "elasticsearch", "kibana", "phpmyadmin",
})
_EXPOSED_SVC_SCORE     = 4

THRESHOLD_HIGH   = 10
THRESHOLD_MEDIUM = 5

# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

class ReconIntelEngine:
    """
    Rule-based additive scoring engine.

    score_host() operates on raw lists and has no dependency on the state
    graph — it can be used standalone for unit tests or ad-hoc analysis.

    analyze_target() reads from the rek_state singleton and runs score_host()
    across every host in the target's graph, returning sorted priority buckets.
    """

    # ------------------------------------------------------------------ #
    # Core scoring unit                                                    #
    # ------------------------------------------------------------------ #

    def score_host(
        self,
        host:       str,
        ports:      List[int],
        endpoints:  List[str],
        tech_stack: List[str],
    ) -> dict:
        """
        Apply all four scoring rules to a single host.

        Deduplication policy
        --------------------
          - Each keyword   counts at most once per host
          - Each port      counts once (ports already unique in state graph)
          - Each sensitive path pattern counts at most once per host
          - Each exposed service counts at most once per host
        """
        score   = 0
        reasons = []

        # ---- Rule 1: subdomain keyword scoring -------------------------
        # Split hostname on dots to get labels, then on hyphens to get parts.
        # A keyword must match a complete part (not a substring of a part)
        # to avoid false positives (e.g. "administrator" != "admin").
        matched_kw: set = set()
        for label in host.lower().split("."):
            for part in label.split("-"):
                if part in _SUBDOMAIN_KEYWORDS and part not in matched_kw:
                    score += _SUBDOMAIN_KW_SCORE
                    reasons.append({
                        "rule":  "subdomain_keyword",
                        "match": part,
                        "score": _SUBDOMAIN_KW_SCORE,
                    })
                    matched_kw.add(part)

        # ---- Rule 2: suspicious port scoring ---------------------------
        for port in ports:
            if int(port) in _SUSPICIOUS_PORTS:
                score += _SUSPICIOUS_PORT_SCORE
                reasons.append({
                    "rule":  "suspicious_port",
                    "match": port,
                    "score": _SUSPICIOUS_PORT_SCORE,
                })

        # ---- Rule 3: sensitive endpoint scoring ------------------------
        # Parse the path from each URL and match against the sensitive set.
        # Each pattern counted at most once per host regardless of how many
        # URLs match it.
        matched_paths: set = set()
        for url in endpoints:
            try:
                path = urlparse(url).path.lower().rstrip("/") or "/"
            except Exception:
                path = url.lower()
            for sensitive in _SENSITIVE_PATHS:
                if (
                    sensitive not in matched_paths
                    and (path == sensitive or path.startswith(sensitive + "/"))
                ):
                    score += _SENSITIVE_PATH_SCORE
                    reasons.append({
                        "rule":        "sensitive_endpoint",
                        "match":       sensitive,
                        "score":       _SENSITIVE_PATH_SCORE,
                        "example_url": url,
                    })
                    matched_paths.add(sensitive)

        # ---- Rule 4: exposed service / technology scoring --------------
        matched_svc: set = set()
        for tech in tech_stack:
            tech_lower = tech.lower()
            for service in _EXPOSED_SERVICES:
                if service not in matched_svc and service in tech_lower:
                    score += _EXPOSED_SVC_SCORE
                    reasons.append({
                        "rule":       "exposed_service",
                        "match":      service,
                        "score":      _EXPOSED_SVC_SCORE,
                        "technology": tech,
                    })
                    matched_svc.add(service)

        priority = (
            "high"   if score >= THRESHOLD_HIGH   else
            "medium" if score >= THRESHOLD_MEDIUM else
            "low"
        )

        return {
            "host":      host,
            "score":     score,
            "priority":  priority,
            "reasons":   reasons,
            "open_ports": ports,
            "tech_stack": tech_stack,
        }

    # ------------------------------------------------------------------ #
    # Target-level analysis                                                #
    # ------------------------------------------------------------------ #

    def analyze_target(self, target: str) -> dict:
        """
        Pull all hosts for target from the state graph, score each one,
        and return sorted priority buckets with scoring metadata.
        """
        from rek_state import state_graph

        _ilog.info("SCORING_ENGINE_STARTED target=%s", target)
        t0 = time.time()

        snap = state_graph.get_target_state(target)

        # Collect all hosts: root domain + every known subdomain
        hosts: set = {target}
        for sub in snap.get("subdomains", []):
            hosts.add(sub["fqdn"])

        findings = []
        for host in sorted(hosts):
            ports     = state_graph.get_open_ports(host)
            endpoints = state_graph.get_endpoints(host)
            tech      = state_graph.get_technology_stack(host)
            finding   = self.score_host(host, ports, endpoints, tech)
            findings.append(finding)
            if finding["priority"] == "high":
                _ilog.info(
                    "HIGH_PRIORITY_TARGET host=%s score=%d reasons=%d",
                    host, finding["score"], len(finding["reasons"]),
                )

        # Primary sort: score descending; secondary sort: host alphabetically
        findings.sort(key=lambda x: (-x["score"], x["host"]))

        high   = [f for f in findings if f["priority"] == "high"]
        medium = [f for f in findings if f["priority"] == "medium"]
        low    = [f for f in findings if f["priority"] == "low"]

        elapsed = round(time.time() - t0, 3)
        _ilog.info(
            "SCORING_ENGINE_COMPLETED target=%s hosts=%d high=%d medium=%d low=%d elapsed=%.3fs",
            target, len(findings), len(high), len(medium), len(low), elapsed,
        )

        return {
            "target":          target,
            "hosts_analyzed":  len(findings),
            "high_priority":   high,
            "medium_priority": medium,
            "low_priority":    low,
            "scoring_metadata": {
                "threshold_high":         THRESHOLD_HIGH,
                "threshold_medium":       THRESHOLD_MEDIUM,
                "rules_applied":          4,
                "rule_names": [
                    "subdomain_keyword",
                    "suspicious_port",
                    "sensitive_endpoint",
                    "exposed_service",
                ],
                "execution_time_seconds": elapsed,
            },
        }

    def get_top_targets(self, target: str, limit: int = 10) -> List[dict]:
        """Return top-N scored findings across all priority tiers."""
        result = self.analyze_target(target)
        combined = (
            result["high_priority"]
            + result["medium_priority"]
            + result["low_priority"]
        )
        return combined[:limit]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

intel_engine = ReconIntelEngine()

# ---------------------------------------------------------------------------
# CLI formatting helpers
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_GREEN  = "\033[92m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"


def _c(text: str, code: str) -> str:
    """Apply ANSI colour only when stdout is a real terminal."""
    return f"{code}{text}{_RESET}" if sys.stdout.isatty() else text


def _print_analysis(result: dict) -> None:
    target = result["target"]
    meta   = result["scoring_metadata"]

    print()
    print(_c(f"REK Intelligence Analysis — {target}", _BOLD + _CYAN))
    print(f"  Hosts analyzed : {result['hosts_analyzed']}")
    print(f"  Thresholds     : high >= {meta['threshold_high']}  |  medium >= {meta['threshold_medium']}")
    print(f"  Rules          : {', '.join(meta['rule_names'])}")
    print()

    tiers = [
        ("high_priority",   "HIGH PRIORITY",   _RED),
        ("medium_priority", "MEDIUM PRIORITY", _YELLOW),
        ("low_priority",    "LOW PRIORITY",    _GREEN),
    ]

    for key, label, colour in tiers:
        findings = result[key]
        print(_c(f"[ {label} — {len(findings)} host(s) ]", colour))
        if not findings:
            print("  (none)")
        for f in findings:
            print(_c(f"  {f['host']:55s}  score={f['score']}", colour))
            for r in f["reasons"]:
                extra = ""
                if r.get("example_url"):
                    extra = f"  → {r['example_url']}"
                elif r.get("technology"):
                    extra = f"  → {r['technology']}"
                print(f"    + [{r['rule']}] {r['match']}  (+{r['score']}){extra}")
            if f["open_ports"]:
                print(f"    ports      : {f['open_ports']}")
            if f["tech_stack"]:
                print(f"    tech_stack : {f['tech_stack']}")
        print()

    print(f"Analysis completed in {meta['execution_time_seconds']}s")
    print()


def _print_top(findings: List[dict], limit: int) -> None:
    print()
    print(_c(f"REK Top {limit} Investigation Targets", _BOLD + _CYAN))
    print()

    if not findings:
        print("  No findings in state graph. Run a scan first.")
        print()
        return

    for i, f in enumerate(findings, 1):
        colour = _RED if f["priority"] == "high" else (
                 _YELLOW if f["priority"] == "medium" else _GREEN)
        tag = f["priority"].upper()
        print(_c(f"  [{i:2d}] [{tag:6s}] score={f['score']:3d}  {f['host']}", colour))
        for r in f["reasons"]:
            print(f"         + [{r['rule']}] {r['match']}")
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="rek_intel",
        description="REK Intelligence Engine — deterministic finding prioritization",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_analyze = sub.add_parser("analyze", help="Full prioritized analysis for a target")
    p_analyze.add_argument("target", help="Target domain (e.g., example.com)")
    p_analyze.add_argument("--json", action="store_true", dest="raw_json",
                           help="Output raw JSON instead of formatted report")

    p_top = sub.add_parser("top", help="Show top-ranked investigation targets")
    p_top.add_argument("target", help="Target domain (e.g., example.com)")
    p_top.add_argument("--limit", type=int, default=10,
                       help="Number of results to show (default: 10)")
    p_top.add_argument("--json", action="store_true", dest="raw_json",
                       help="Output raw JSON instead of formatted list")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "analyze":
        result = intel_engine.analyze_target(args.target)
        if args.raw_json:
            print(json.dumps(result, indent=2))
        else:
            _print_analysis(result)

    elif args.command == "top":
        findings = intel_engine.get_top_targets(args.target, args.limit)
        if args.raw_json:
            print(json.dumps(findings, indent=2))
        else:
            _print_top(findings, args.limit)


if __name__ == "__main__":
    main()
