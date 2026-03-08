#!/usr/bin/env python3
"""
rek_domain_gate.py

Two-phase domain approval gate for recon pipeline safety.

Prevents automated expansion into newly discovered root domains that were
not explicitly authorized by the operator. Sits between asset discovery
and the scope guard in the pipeline:

  discovery → normalization → asset_graph → domain_safety_gate
  → scope_guard → scheduler → execution

Core principle
--------------
  Discovery may observe widely.
  Expansion into new root domains requires explicit operator approval.

Problem it solves
-----------------
  Recon pipelines frequently discover third-party infrastructure through
  passive DNS, TLS SANs, CDN edges, or vendor redirects:

    target.com → cdn.target.com → vendor-cloudfront.net

  Without a gate, the engine may begin scanning vendor-cloudfront.net,
  violating third-party infrastructure boundaries and bug-bounty scope.

Gate behaviour
--------------
  Phase 1 — discovery (unrestricted):
    Passive observation of hostnames is allowed regardless of root domain.

  Phase 2 — expansion / execution (gated):
    Before any active tool runs against a host, the root domain is
    extracted and checked:

      approved  → execution proceeds to scope_guard
      pending   → execution blocked; domain queued for review
      rejected  → execution permanently blocked

Auto-approval
-------------
  Root domains that have been explicitly added to the recon state graph
  as targets (via upsert_target) are automatically treated as approved.
  This means that for a normal recon workflow:

    tool_enumerate_subdomains("example.com")
        ↓
    state_graph.upsert_target("example.com")  ← auto-approved
        ↓
    all *.example.com hosts are allowed through the gate

  Only NEW root domains discovered through passive association require
  explicit operator approval.

Storage
-------
  state/pending_domains.json:
  {
    "approved": { "example.com": {"approved_at": "...", "source": "..."} },
    "pending":  { "vendor.net":  {"domain": "...", "discovered_from": "...",
                                   "discovery_method": "...", "first_seen": "...",
                                   "status": "pending"} },
    "rejected": { "evil.com":    {"rejected_at": "..."} }
  }

CLI usage
---------
  python rek_domain_gate.py list                — show all pending domains
  python rek_domain_gate.py approve <domain>    — approve a pending domain
  python rek_domain_gate.py reject  <domain>    — reject a pending domain
  python rek_domain_gate.py status  <hostname>  — check gate status for host
  python rek_domain_gate.py check   <hostname>  — same as status, exit 1 if blocked
"""

import argparse
import ipaddress
import json
import logging
import logging.handlers
import os
import sys
import threading
from datetime import datetime, timezone
from typing import List, Optional

_MODULE_DIR  = os.path.dirname(os.path.abspath(__file__))
_STORAGE_PATH = os.path.join(_MODULE_DIR, "state", "pending_domains.json")
_LOG_PATH     = os.path.join(_MODULE_DIR, "logs", "domain_gate.log")

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

_dglog = logging.getLogger("rek_domain_gate")
_dglog.setLevel(logging.INFO)
_dglog.propagate = False

os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)
_lfh = logging.handlers.RotatingFileHandler(
    _LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_lfh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_dglog.addHandler(_lfh)

# ---------------------------------------------------------------------------
# Root domain extraction
# ---------------------------------------------------------------------------

# Known multi-part public suffixes (subset of PSL sufficient for common recon targets)
_MULTI_PART_PSL = frozenset({
    "co.uk", "co.nz", "co.jp", "co.za", "co.in", "co.ke", "co.tz",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.ar", "com.pe",
    "org.uk", "org.au", "net.au", "net.br", "gov.uk", "edu.au", "edu.cn",
    "ac.uk", "me.uk",
})

try:
    import tldextract as _tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False


def extract_root_domain(hostname: str) -> Optional[str]:
    """
    Extract the registrable root domain from a hostname.

    Returns None if hostname is an IP address (no domain gate applies).

    Uses tldextract when available; falls back to a PSL-aware heuristic
    covering the most common TLDs for recon work.
    """
    hostname = hostname.lower().strip().rstrip(".")
    if not hostname:
        return None

    # IP addresses pass through — scope guard handles them, not the domain gate
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass

    if _HAS_TLDEXTRACT:
        ext = _tldextract.extract(hostname)
        if not ext.domain or not ext.suffix:
            return None
        return f"{ext.domain}.{ext.suffix}"

    # Fallback: PSL-aware heuristic
    labels = hostname.split(".")
    if len(labels) < 2:
        return None
    if len(labels) >= 3:
        two_part = ".".join(labels[-2:])
        if two_part in _MULTI_PART_PSL:
            return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# ---------------------------------------------------------------------------
# DomainSafetyGate
# ---------------------------------------------------------------------------

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


class DomainSafetyGate:
    """
    Thread-safe, persistent two-phase domain approval gate.

    Approved, pending, and rejected domains are stored in
    state/pending_domains.json with atomic writes.
    """

    def __init__(self, storage_path: str = _STORAGE_PATH):
        self._path = storage_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(storage_path), exist_ok=True)
        self._data = self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> dict:
        if os.path.exists(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data.setdefault("approved", {})
                data.setdefault("pending",  {})
                data.setdefault("rejected", {})
                return data
            except (json.JSONDecodeError, OSError) as exc:
                _dglog.warning("Domain gate storage unreadable (%s) — starting fresh.", exc)
        return {"approved": {}, "pending": {}, "rejected": {}}

    def _flush(self) -> None:
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)
        os.replace(tmp, self._path)

    # ------------------------------------------------------------------
    # Internal approval check
    # ------------------------------------------------------------------

    def _is_root_approved(self, root: str) -> bool:
        """
        Check if a root domain is approved.

        Checks in order:
        1. Explicit approval in gate storage
        2. Known root in recon state graph (auto-approved because operator
           intentionally added it as a tracking target)
        """
        if root in self._data["approved"]:
            return True
        # Auto-approve: root domains the operator explicitly added as targets
        try:
            from rek_state import state_graph
            known_targets = {t["domain"] for t in state_graph.list_targets()}
            if root in known_targets:
                return True
        except Exception:
            pass
        return False

    def _is_root_rejected(self, root: str) -> bool:
        return root in self._data["rejected"]

    # ------------------------------------------------------------------
    # Core gate function
    # ------------------------------------------------------------------

    def domain_safety_gate(
        self,
        hostname: str,
        discovered_from: str = "",
        discovery_method: str = "unknown",
    ) -> bool:
        """
        Determine if expansion/execution against hostname is allowed.

        Algorithm
        ---------
        1. Extract root domain from hostname.
        2. If no root (IP address): pass through — scope guard handles IPs.
        3. If root is approved (explicit or via state graph target): allow.
        4. If root is rejected: block permanently.
        5. If root is pending: block (already queued for review).
        6. NEW root: record as pending, log, block.

        Parameters
        ----------
        hostname         : asset to check (domain, subdomain, URL, IP)
        discovered_from  : parent asset that led to this discovery (for log)
        discovery_method : source mechanism (passive_dns, ct_log, etc.)

        Returns
        -------
        True  — execution allowed
        False — execution blocked (pending or rejected)
        """
        from rek_scope import ScopeGuard
        hostname = ScopeGuard._normalize(hostname)

        root = extract_root_domain(hostname)

        # IP addresses: no domain gate — pass to scope guard
        if root is None:
            return True

        with self._lock:
            approved = self._is_root_approved(root)
            if approved:
                return True

            if self._is_root_rejected(root):
                _dglog.info(
                    "DOMAIN_GATE_BLOCKED hostname=%s root=%s status=rejected "
                    "discovered_from=%s method=%s action=blocked",
                    hostname, root, discovered_from, discovery_method,
                )
                return False

            if root in self._data["pending"]:
                _dglog.info(
                    "DOMAIN_GATE_BLOCKED hostname=%s root=%s status=pending "
                    "discovered_from=%s method=%s action=blocked",
                    hostname, root, discovered_from, discovery_method,
                )
                return False

            # New, unseen root domain — record as pending
            self._data["pending"][root] = {
                "domain":           root,
                "discovered_from":  discovered_from or hostname,
                "discovery_method": discovery_method,
                "first_seen":       _ts(),
                "status":           "pending",
            }
            self._flush()
            _dglog.info(
                "DOMAIN_GATE_PENDING hostname=%s root=%s status=pending_approval "
                "discovered_from=%s method=%s action=blocked",
                hostname, root, discovered_from, discovery_method,
            )
            return False

    # ------------------------------------------------------------------
    # Operator approval workflow
    # ------------------------------------------------------------------

    def approve_domain(self, domain: str) -> dict:
        """
        Approve a pending (or any) root domain for expansion and execution.

        Moves domain from pending to approved. Idempotent for already-approved.
        """
        domain = domain.lower().strip()
        with self._lock:
            if domain in self._data["approved"]:
                return {
                    "domain":  domain,
                    "result":  "already_approved",
                    "status":  "approved",
                }
            prev_status = "new"
            if domain in self._data["pending"]:
                del self._data["pending"][domain]
                prev_status = "pending"
            if domain in self._data["rejected"]:
                del self._data["rejected"][domain]
                prev_status = "rejected"

            self._data["approved"][domain] = {
                "domain":      domain,
                "approved_at": _ts(),
                "prev_status": prev_status,
            }
            self._flush()

        _dglog.info("DOMAIN_APPROVED domain=%s prev_status=%s", domain, prev_status)
        return {"domain": domain, "result": "approved", "status": "approved",
                "prev_status": prev_status}

    def reject_domain(self, domain: str) -> dict:
        """
        Permanently reject a domain, blocking all future expansion/execution.

        Moves domain from pending to rejected. Idempotent for already-rejected.
        """
        domain = domain.lower().strip()
        with self._lock:
            if domain in self._data["rejected"]:
                return {
                    "domain": domain,
                    "result": "already_rejected",
                    "status": "rejected",
                }
            prev_status = "new"
            if domain in self._data["pending"]:
                del self._data["pending"][domain]
                prev_status = "pending"
            if domain in self._data["approved"]:
                del self._data["approved"][domain]
                prev_status = "approved"

            self._data["rejected"][domain] = {
                "domain":      domain,
                "rejected_at": _ts(),
                "prev_status": prev_status,
            }
            self._flush()

        _dglog.info("DOMAIN_REJECTED domain=%s prev_status=%s", domain, prev_status)
        return {"domain": domain, "result": "rejected", "status": "rejected",
                "prev_status": prev_status}

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def list_pending(self) -> List[dict]:
        with self._lock:
            return list(self._data["pending"].values())

    def list_approved(self) -> List[dict]:
        with self._lock:
            return list(self._data["approved"].values())

    def list_rejected(self) -> List[dict]:
        with self._lock:
            return list(self._data["rejected"].values())

    def get_status(self, hostname: str) -> dict:
        """Return the gate status for a hostname (checks its root domain)."""
        from rek_scope import ScopeGuard
        hostname = ScopeGuard._normalize(hostname)
        root = extract_root_domain(hostname)

        if root is None:
            return {
                "hostname":  hostname,
                "root":      None,
                "status":    "pass_through",
                "reason":    "ip_address_no_domain_gate",
                "allowed":   True,
            }

        with self._lock:
            if self._is_root_approved(root):
                return {
                    "hostname": hostname, "root": root,
                    "status": "approved", "allowed": True,
                }
            if self._is_root_rejected(root):
                return {
                    "hostname": hostname, "root": root,
                    "status": "rejected", "allowed": False,
                }
            if root in self._data["pending"]:
                rec = self._data["pending"][root]
                return {
                    "hostname":         hostname,
                    "root":             root,
                    "status":           "pending",
                    "allowed":          False,
                    "discovered_from":  rec.get("discovered_from"),
                    "discovery_method": rec.get("discovery_method"),
                    "first_seen":       rec.get("first_seen"),
                }
        return {
            "hostname": hostname, "root": root,
            "status": "unknown", "allowed": False,
            "note": "not yet seen by gate",
        }

    def get_summary(self) -> dict:
        with self._lock:
            return {
                "approved": len(self._data["approved"]),
                "pending":  len(self._data["pending"]),
                "rejected": len(self._data["rejected"]),
            }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

domain_gate = DomainSafetyGate()

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


def _print_pending(records: List[dict]) -> None:
    print()
    print(_c(f"REK Domain Safety Gate — Pending Approval ({len(records)})", _BOLD + _CYAN))
    print()
    if not records:
        print("  No domains pending approval.")
        print()
        return
    for r in records:
        print(_c(f"  {r['domain']:45s}", _YELLOW), end="")
        print(f"  via={r.get('discovery_method','?')}  "
              f"from={r.get('discovered_from','?')}  "
              f"seen={r.get('first_seen','?')[:19]}")
    print()
    print("  To approve: python rek_domain_gate.py approve <domain>")
    print("  To reject:  python rek_domain_gate.py reject  <domain>")
    print()


def _print_status(result: dict) -> None:
    status  = result["status"]
    allowed = result["allowed"]
    colour  = _GREEN if allowed else (_YELLOW if status == "pending" else _RED)
    print()
    print(_c(f"REK Domain Safety Gate — Status Check", _BOLD + _CYAN))
    print(f"  Hostname : {result['hostname']}")
    print(f"  Root     : {result.get('root', 'N/A (IP)')}")
    print(_c(f"  Status   : {status.upper()}", colour))
    print(f"  Allowed  : {allowed}")
    if result.get("discovered_from"):
        print(f"  From     : {result['discovered_from']}")
    if result.get("first_seen"):
        print(f"  First seen: {result['first_seen'][:19]}")
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="rek_domain_gate",
        description="REK Domain Safety Gate — two-phase domain approval",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("list",    help="List all pending domains awaiting approval")

    p_approve = sub.add_parser("approve", help="Approve a pending domain")
    p_approve.add_argument("domain")

    p_reject = sub.add_parser("reject",  help="Reject a pending domain")
    p_reject.add_argument("domain")

    p_status = sub.add_parser("status",  help="Show gate status for a hostname")
    p_status.add_argument("hostname")

    p_check = sub.add_parser("check",    help="Check hostname (exit 1 if blocked)")
    p_check.add_argument("hostname")

    for p in (p_approve, p_reject, p_status, p_check):
        p.add_argument("--json", action="store_true", dest="raw_json")
    sub.parsers_dict = getattr(sub, "_name_parser_map", {})

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "list":
        records = domain_gate.list_pending()
        _print_pending(records)

    elif args.command == "approve":
        result = domain_gate.approve_domain(args.domain)
        if getattr(args, "raw_json", False):
            print(json.dumps(result, indent=2))
        else:
            colour = _GREEN if result["result"] in ("approved",) else _YELLOW
            print(_c(f"\n  {args.domain} → {result['result'].upper()}\n", colour))

    elif args.command == "reject":
        result = domain_gate.reject_domain(args.domain)
        if getattr(args, "raw_json", False):
            print(json.dumps(result, indent=2))
        else:
            colour = _RED if result["result"] in ("rejected",) else _YELLOW
            print(_c(f"\n  {args.domain} → {result['result'].upper()}\n", colour))

    elif args.command in ("status", "check"):
        result = domain_gate.get_status(args.hostname)
        if getattr(args, "raw_json", False):
            print(json.dumps(result, indent=2))
        else:
            _print_status(result)
        if args.command == "check" and not result["allowed"]:
            sys.exit(1)


if __name__ == "__main__":
    main()
