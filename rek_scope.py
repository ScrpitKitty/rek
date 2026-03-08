#!/usr/bin/env python3
"""
rek_scope.py

Deterministic scope-compliance enforcement for the recon orchestration engine.

Scope is configured via state/scope.json. The guard is consulted by every
execution pathway before any active tool is invoked. LLM reasoning never
overrides this layer.

Pipeline position
-----------------
  discovery_tools → normalization → asset_tracking → scope_guard ← HERE
  → suppression_engine → scheduling → execution

Configuration (state/scope.json)
---------------------------------
  {
    "allowed_domains":         ["example.com", "api.example.com"],
    "allowed_domain_suffixes": [".example.com"],
    "allowed_ip_ranges":       ["192.0.2.0/24"],
    "excluded_domains":        ["cdn.example.com"],
    "strict_mode":             false
  }

  strict_mode:
    false (default) — permissive when no config file exists (allows all)
    true            — denies all when no config file exists

Resolution order
----------------
  1. excluded_domains match       → out_of_scope  (exclusions always win)
  2. exact allowed_domains match  → in_scope  (scope_reason: exact_match)
  3. allowed_domain_suffixes hit  → in_scope  (scope_reason: subdomain_match)
  4. IP address in allowed_ip_ranges → in_scope (scope_reason: ip_range)
  5. No match                     → out_of_scope

CLI usage
---------
  python rek_scope.py check <asset>          — check if asset is in scope
  python rek_scope.py check <a> <b> ...      — check multiple assets
  python rek_scope.py show                   — display current scope config
  python rek_scope.py init  <domain>         — write starter scope.json
"""

import argparse
import ipaddress
import json
import logging
import logging.handlers
import os
import sys
import threading
from typing import Dict, List, Optional
from urllib.parse import urlparse

_MODULE_DIR  = os.path.dirname(os.path.abspath(__file__))
_CONFIG_PATH = os.path.join(_MODULE_DIR, "state", "scope.json")
_LOG_PATH    = os.path.join(_MODULE_DIR, "logs", "recon_scope.log")

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

_sclog = logging.getLogger("rek_scope")
_sclog.setLevel(logging.INFO)
_sclog.propagate = False

os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)
_sfh = logging.handlers.RotatingFileHandler(
    _LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_sfh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_sclog.addHandler(_sfh)

# ---------------------------------------------------------------------------
# Scope reasons
# ---------------------------------------------------------------------------

REASON_EXACT_MATCH      = "exact_match"
REASON_SUBDOMAIN_MATCH  = "subdomain_match"
REASON_IP_RANGE         = "ip_range"
REASON_EXCLUDED         = "excluded"
REASON_OUT_OF_SCOPE     = "out_of_scope"
REASON_PERMISSIVE       = "permissive_no_config"
REASON_STRICT_NO_CONFIG = "strict_no_config"


# ---------------------------------------------------------------------------
# ScopeGuard
# ---------------------------------------------------------------------------

class ScopeGuard:
    """
    Thread-safe, file-backed scope enforcement gate.

    All public methods are safe to call from any thread. The config is
    loaded at construction time and can be reloaded via reload().
    """

    def __init__(self, config_path: str = _CONFIG_PATH):
        self._path       = config_path
        self._lock       = threading.Lock()
        self._loaded     = False
        self._strict     = False
        self._allowed_domains:   set             = set()
        self._allowed_suffixes:  List[str]       = []
        self._allowed_networks:  List             = []
        self._excluded_domains:  set             = set()
        self._load()

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Read and parse scope.json. Resets all config state."""
        if not os.path.exists(self._path):
            self._loaded = False
            _sclog.warning(
                "SCOPE_CONFIG_MISSING path=%s — running in %s mode",
                self._path,
                "STRICT (deny all)" if self._strict else "PERMISSIVE (allow all)",
            )
            return

        try:
            with open(self._path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            _sclog.error("SCOPE_CONFIG_UNREADABLE path=%s error=%s", self._path, exc)
            self._loaded = False
            return

        self._strict           = bool(cfg.get("strict_mode", False))
        self._allowed_domains  = {d.lower().strip() for d in cfg.get("allowed_domains", [])}
        self._allowed_suffixes = [
            s.lower().strip() if s.startswith(".") else "." + s.lower().strip()
            for s in cfg.get("allowed_domain_suffixes", [])
        ]
        self._excluded_domains = {d.lower().strip() for d in cfg.get("excluded_domains", [])}

        self._allowed_networks = []
        for cidr in cfg.get("allowed_ip_ranges", []):
            try:
                self._allowed_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                _sclog.warning("SCOPE_INVALID_CIDR cidr=%s", cidr)

        self._loaded = True
        _sclog.info(
            "SCOPE_CONFIG_LOADED path=%s domains=%d suffixes=%d networks=%d excluded=%d strict=%s",
            self._path,
            len(self._allowed_domains),
            len(self._allowed_suffixes),
            len(self._allowed_networks),
            len(self._excluded_domains),
            self._strict,
        )

    def reload(self) -> None:
        """Force reload the scope configuration from disk."""
        with self._lock:
            self._load()

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize(target: str) -> str:
        """
        Extract the hostname from a URL, IP, or bare domain.

        Strips scheme, path, query, port; lowercases.
        """
        target = target.strip()
        if "://" in target:
            parsed = urlparse(target)
            return (parsed.hostname or "").lower()
        # Handle host:port without scheme
        if ":" in target and not target.startswith("["):
            target = target.split(":")[0]
        return target.lower().rstrip(".")

    # ------------------------------------------------------------------
    # Core decision
    # ------------------------------------------------------------------

    def in_scope(self, target: str) -> dict:
        """
        Check whether target is within the declared scope.

        Parameters
        ----------
        target : domain, subdomain, URL, or IP address

        Returns
        -------
        {
            "asset":        <normalised host>,
            "allowed":      True | False,
            "scope_reason": <reason string>
        }
        """
        host = self._normalize(target)

        with self._lock:
            loaded    = self._loaded
            strict    = self._strict
            excluded  = self._excluded_domains
            allowed_d = self._allowed_domains
            suffixes  = self._allowed_suffixes
            networks  = self._allowed_networks

        # No config loaded
        if not loaded:
            if strict:
                _sclog.info(
                    "SCOPE_BLOCKED asset=%s reason=strict_no_config", host,
                )
                return {"asset": host, "allowed": False, "scope_reason": REASON_STRICT_NO_CONFIG}
            return {"asset": host, "allowed": True, "scope_reason": REASON_PERMISSIVE}

        # Rule 1: exclusions always override allows
        if host in excluded:
            _sclog.info("SCOPE_BLOCKED asset=%s reason=excluded", host)
            return {"asset": host, "allowed": False, "scope_reason": REASON_EXCLUDED}

        # Rule 2: exact domain match
        if host in allowed_d:
            return {"asset": host, "allowed": True, "scope_reason": REASON_EXACT_MATCH}

        # Rule 3: suffix (subdomain) match
        for suffix in suffixes:
            if host.endswith(suffix):
                return {"asset": host, "allowed": True, "scope_reason": REASON_SUBDOMAIN_MATCH}

        # Rule 4: IP range
        try:
            ip = ipaddress.ip_address(host)
            for net in networks:
                if ip in net:
                    return {"asset": host, "allowed": True, "scope_reason": REASON_IP_RANGE}
        except ValueError:
            pass  # not an IP address — continue to out_of_scope

        _sclog.info("SCOPE_BLOCKED asset=%s reason=out_of_scope", host)
        return {"asset": host, "allowed": False, "scope_reason": REASON_OUT_OF_SCOPE}

    def check_and_log(self, target: str, discovered_via: str = "") -> bool:
        """
        Convenience wrapper: call in_scope(), log a structured block event
        if out-of-scope, return the allowed boolean.

        Parameters
        ----------
        target        : asset to check
        discovered_via: source tool name for log context
        """
        result = self.in_scope(target)
        if not result["allowed"]:
            _sclog.info(
                "SCOPE_VIOLATION asset=%s status=out_of_scope reason=%s "
                "discovered_via=%s action=blocked",
                result["asset"],
                result["scope_reason"],
                discovered_via or "unknown",
            )
        return result["allowed"]

    # ------------------------------------------------------------------
    # Config dump (for CLI / MCP show)
    # ------------------------------------------------------------------

    def get_config(self) -> dict:
        """Return the current scope configuration as a plain dict."""
        with self._lock:
            return {
                "config_path":              self._path,
                "config_loaded":            self._loaded,
                "strict_mode":              self._strict,
                "allowed_domains":          sorted(self._allowed_domains),
                "allowed_domain_suffixes":  self._allowed_suffixes,
                "allowed_ip_ranges":        [str(n) for n in self._allowed_networks],
                "excluded_domains":         sorted(self._excluded_domains),
            }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

scope_guard = ScopeGuard()

# ---------------------------------------------------------------------------
# Scope config initialiser (CLI helper)
# ---------------------------------------------------------------------------

def _init_scope_config(domain: str) -> None:
    """Write a starter scope.json for the given root domain."""
    os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
    cfg = {
        "allowed_domains":         [domain],
        "allowed_domain_suffixes": [f".{domain}"],
        "allowed_ip_ranges":       [],
        "excluded_domains":        [],
        "strict_mode":             False,
    }
    with open(_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    print(f"  Scope config written to: {_CONFIG_PATH}")
    print(f"  Allowed: {domain}  +  *.{domain}")
    print("  Edit the file to add IP ranges or exclusions.")


# ---------------------------------------------------------------------------
# CLI formatting
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"
_GREEN  = "\033[92m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if sys.stdout.isatty() else text


def _print_check(results: List[dict]) -> None:
    print()
    print(_c("REK Scope Guard — Asset Check", _BOLD + _CYAN))
    print()
    for r in results:
        colour = _GREEN if r["allowed"] else _RED
        mark   = "ALLOWED" if r["allowed"] else "BLOCKED"
        print(_c(f"  [{mark:7s}]  {r['asset']:55s}  ({r['scope_reason']})", colour))
    print()


def _print_show(cfg: dict) -> None:
    print()
    print(_c("REK Scope Guard — Current Configuration", _BOLD + _CYAN))
    print(f"  Config file   : {cfg['config_path']}")
    print(f"  Loaded        : {cfg['config_loaded']}")
    print(f"  Strict mode   : {cfg['strict_mode']}")
    print()
    print(_c("  Allowed domains:", _GREEN))
    for d in cfg["allowed_domains"] or ["(none)"]:
        print(f"    {d}")
    print(_c("  Allowed suffixes:", _GREEN))
    for s in cfg["allowed_domain_suffixes"] or ["(none)"]:
        print(f"    {s}")
    print(_c("  Allowed IP ranges:", _GREEN))
    for r in cfg["allowed_ip_ranges"] or ["(none)"]:
        print(f"    {r}")
    print(_c("  Excluded domains:", _RED))
    for d in cfg["excluded_domains"] or ["(none)"]:
        print(f"    {d}")
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="rek_scope",
        description="REK Scope Guard — deterministic scope enforcement",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_check = sub.add_parser("check", help="Check if one or more assets are in scope")
    p_check.add_argument("assets", nargs="+", help="Domain, subdomain, URL, or IP to check")
    p_check.add_argument("--json", action="store_true", dest="raw_json")

    p_show = sub.add_parser("show", help="Display current scope configuration")
    p_show.add_argument("--json", action="store_true", dest="raw_json")

    p_init = sub.add_parser("init", help="Create a starter scope.json for a root domain")
    p_init.add_argument("domain", help="Root domain to allow (e.g., example.com)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "check":
        results = [scope_guard.in_scope(a) for a in args.assets]
        if args.raw_json:
            print(json.dumps(results, indent=2))
        else:
            _print_check(results)
        # Exit code 1 if any asset is out of scope
        if not all(r["allowed"] for r in results):
            sys.exit(1)

    elif args.command == "show":
        cfg = scope_guard.get_config()
        if args.raw_json:
            print(json.dumps(cfg, indent=2))
        else:
            _print_show(cfg)

    elif args.command == "init":
        if os.path.exists(_CONFIG_PATH):
            print(f"\n  scope.json already exists at {_CONFIG_PATH}")
            print("  Delete it first if you want to reinitialise.\n")
            sys.exit(1)
        _init_scope_config(args.domain)


if __name__ == "__main__":
    main()
