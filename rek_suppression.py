#!/usr/bin/env python3
"""
rek_suppression.py

False-positive suppression engine for recon asset management.

Evaluates discovered subdomains against six deterministic suppression rules
and two promotion rules. Suppressed assets are marked in the state graph but
never deleted — all decisions are reversible and fully logged.

Suppression rules
-----------------
  Rule 1 — invalid_fqdn              → suppressed  (always)
  Rule 2 — single_weak_source        → deferred    (weak single-source discovery)
  Rule 3 — repeated_resolution_fail  → suppressed  (≥2 failures, low confidence)
  Rule 4 — historical_only_asset     → deferred    (passive-DNS only, unverified)
  Rule 5 — duplicate_alias           → merged      (normalises to known canonical)
  Rule 6 — stale_low_confidence      → suppressed  (candidate, >30d old, low score)

Promotion rules
---------------
  promote_to_verified — confidence ≥ 4 OR ≥2 strong independent sources
  promote_to_active   — candidate/deferred with >1 source

Asset status semantics
----------------------
  verified   — confirmed by multiple sources or successful validation
  active     — usable, eligible for normal scheduling
  candidate  — discovered but not yet strongly confirmed (default)
  deferred   — plausible but lower-value; skipped in standard scheduling
  suppressed — excluded from normal scheduling; preserved for audit

CLI usage
---------
  python rek_suppression.py run     <target>         [--json]
  python rek_suppression.py list    <target>         [--json]
  python rek_suppression.py review  <target>         [--json]
  python rek_suppression.py restore <asset_fqdn>     [--json]
"""

import argparse
import json
import logging
import logging.handlers
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _MODULE_DIR)

_LOG_PATH = os.path.join(_MODULE_DIR, "logs", "false_positive_suppression.log")

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

_splog = logging.getLogger("rek_suppression")
_splog.setLevel(logging.INFO)
_splog.propagate = False

os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)
_sfh = logging.handlers.RotatingFileHandler(
    _LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_sfh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_splog.addHandler(_sfh)

# ---------------------------------------------------------------------------
# Policy constants
# ---------------------------------------------------------------------------

_STALE_DAYS               = 30
_MAX_RESOLUTION_FAILURES  = 2
_CONFIDENCE_WEAK          = 2
_CONFIDENCE_VERIFIED      = 4
_MIN_STRONG_SOURCES       = 2

_SUPPRESSED_STATUSES = frozenset({"suppressed", "merged"})
_DEFERRED_STATUSES   = frozenset({"deferred"})
_ACTIVE_STATUSES     = frozenset({"verified", "active", "candidate"})


# ---------------------------------------------------------------------------
# Suppression evaluation
# ---------------------------------------------------------------------------

def _source_list(rec: dict) -> List[str]:
    """Return the source_list for a subdomain record, back-filling from source_tool."""
    sl = rec.get("source_list")
    if sl:
        return sl
    # Backward compat: records created before suppression fields were added
    return [rec.get("source_tool", "unknown")]


def evaluate_asset(
    subdomain_record: dict,
    known_canonical: set,
) -> Tuple[str, Optional[str]]:
    """
    Apply all six suppression rules (then promotion rules) to a single asset.

    Parameters
    ----------
    subdomain_record  : one entry from state_graph._state["subdomains"]
    known_canonical   : set of canonical FQDNs already seen in this batch
                        (used for Rule 5 duplicate detection)

    Returns
    -------
    (new_status, reason) — reason is None when the status is unchanged
                           or when promoted without a suppression cause.
    """
    from rek_source_trust import (
        get_confidence, count_strong_sources,
        is_passive_dns_only, is_single_weak_source,
    )
    from rek_asset_validation import is_valid_fqdn, canonical_fqdn

    fqdn               = subdomain_record["fqdn"]
    source_list        = _source_list(subdomain_record)
    times_seen         = subdomain_record.get("times_seen", 1)
    resolution_failures = subdomain_record.get("resolution_failures", 0)
    current_status     = subdomain_record.get("suppression_status", "candidate")
    last_seen_iso      = subdomain_record.get("last_seen")

    confidence = get_confidence(source_list)

    # ------------------------------------------------------------------
    # Rule 1: Invalid FQDN — suppressed unconditionally
    # ------------------------------------------------------------------
    if not is_valid_fqdn(fqdn):
        return "suppressed", "invalid_fqdn"

    # ------------------------------------------------------------------
    # Promotion checks — strong evidence overrides suppression rules
    # (except Rule 1 which is absolute)
    #
    # Promotion to verified requires strong-source confirmation:
    #   - confidence >= threshold AND at least one strong source present, OR
    #   - two or more independent strong sources
    # Passive-DNS-only sources alone cannot promote to verified even if
    # their combined weight meets the numeric threshold.
    # ------------------------------------------------------------------
    strong_count = count_strong_sources(source_list)
    if (confidence >= _CONFIDENCE_VERIFIED and strong_count > 0) or strong_count >= _MIN_STRONG_SOURCES:
        if current_status not in ("verified",):
            return "verified", None

    if current_status == "verified":
        # Verified assets are immune to suppression rules
        return "verified", None

    # ------------------------------------------------------------------
    # Rule 5: Duplicate alias — detect before other rules
    # ------------------------------------------------------------------
    canonical = canonical_fqdn(fqdn)
    if canonical in known_canonical and canonical != fqdn:
        return "merged", "duplicate_alias"

    # ------------------------------------------------------------------
    # Rule 2: Single weak source
    # ------------------------------------------------------------------
    if is_single_weak_source(source_list) and times_seen == 1 and confidence <= 1:
        return "deferred", "single_weak_source"

    # ------------------------------------------------------------------
    # Rule 3: Repeated resolution failure
    # ------------------------------------------------------------------
    if resolution_failures >= _MAX_RESOLUTION_FAILURES and confidence <= _CONFIDENCE_WEAK:
        return "suppressed", "repeated_resolution_failure"

    # ------------------------------------------------------------------
    # Rule 4: Historical-only asset (passive DNS only, no live confirmation)
    # ------------------------------------------------------------------
    if is_passive_dns_only(source_list) and current_status != "verified":
        return "deferred", "historical_only_asset"

    # ------------------------------------------------------------------
    # Rule 6: Low-value stale asset
    # ------------------------------------------------------------------
    if current_status == "candidate" and times_seen == 1 and confidence <= _CONFIDENCE_WEAK:
        if last_seen_iso:
            try:
                last = datetime.fromisoformat(last_seen_iso)
                if (datetime.now(timezone.utc) - last) > timedelta(days=_STALE_DAYS):
                    return "suppressed", "stale_low_confidence"
            except (ValueError, TypeError):
                pass

    # ------------------------------------------------------------------
    # Promotion to active: candidate/deferred with >1 confirming source
    # ------------------------------------------------------------------
    if current_status in ("candidate", "deferred") and len(set(source_list)) > 1:
        return "active", None

    # No change warranted
    return current_status, None


# ---------------------------------------------------------------------------
# Suppression engine
# ---------------------------------------------------------------------------

class FalsePositiveSuppressionEngine:
    """
    Evaluates all subdomain assets for a target and applies suppression rules.

    All operations update the state graph in-place. Suppressed records are
    never deleted — their suppression_status field is updated instead.
    """

    # ------------------------------------------------------------------ #
    # Run suppression pass                                                 #
    # ------------------------------------------------------------------ #

    def run_suppression(self, target: str) -> dict:
        """
        Evaluate every subdomain for target and update suppression statuses.

        Returns a summary dict with per-status counts and a full audit list.
        """
        from rek_state import state_graph

        _splog.info("SUPPRESSION_ENGINE_STARTED target=%s", target)
        t0 = time.time()

        snap       = state_graph.get_target_state(target)
        subdomains = snap.get("subdomains", [])

        summary: Dict[str, int] = {
            "total":      len(subdomains),
            "verified":   0,
            "active":     0,
            "candidate":  0,
            "deferred":   0,
            "suppressed": 0,
            "merged":     0,
            "unchanged":  0,
        }
        audit: List[dict] = []

        # Build canonical set from all known subdomains for Rule 5
        known_canonical: set = set()

        for rec in subdomains:
            from rek_asset_validation import canonical_fqdn
            new_status, reason = evaluate_asset(rec, known_canonical)
            old_status = rec.get("suppression_status", "candidate")

            from rek_source_trust import get_confidence
            confidence = get_confidence(_source_list(rec))

            if new_status != old_status:
                state_graph.update_suppression(
                    fqdn=rec["fqdn"],
                    status=new_status,
                    reason=reason,
                    confidence_score=confidence,
                )
                audit_entry = {
                    "fqdn":         rec["fqdn"],
                    "old_status":   old_status,
                    "new_status":   new_status,
                    "reason":       reason,
                    "confidence":   confidence,
                    "sources":      _source_list(rec),
                }
                audit.append(audit_entry)

                if new_status in ("suppressed", "merged"):
                    _splog.info(
                        "ASSET_SUPPRESSED fqdn=%s reason=%s confidence=%d",
                        rec["fqdn"], reason, confidence,
                    )
                elif new_status == "deferred":
                    _splog.info(
                        "ASSET_DEFERRED fqdn=%s reason=%s confidence=%d",
                        rec["fqdn"], reason, confidence,
                    )
                elif new_status == "verified":
                    _splog.info(
                        "ASSET_PROMOTED fqdn=%s new_status=verified confidence=%d",
                        rec["fqdn"], confidence,
                    )
                elif new_status == "active":
                    _splog.info(
                        "ASSET_PROMOTED fqdn=%s new_status=active confidence=%d",
                        rec["fqdn"], confidence,
                    )
            else:
                summary["unchanged"] += 1

            # Track canonical forms for Rule 5 (only non-suppressed assets)
            if new_status not in _SUPPRESSED_STATUSES:
                known_canonical.add(canonical_fqdn(rec["fqdn"]))

            summary[new_status] = summary.get(new_status, 0) + 1

        elapsed = round(time.time() - t0, 3)
        _splog.info(
            "SUPPRESSION_ENGINE_COMPLETED target=%s total=%d suppressed=%d "
            "deferred=%d verified=%d elapsed=%.3fs",
            target, summary["total"], summary.get("suppressed", 0),
            summary.get("deferred", 0), summary.get("verified", 0), elapsed,
        )

        return {
            "target":   target,
            "summary":  summary,
            "audit":    audit,
            "execution_time_seconds": elapsed,
        }

    # ------------------------------------------------------------------ #
    # List suppressed / deferred assets                                    #
    # ------------------------------------------------------------------ #

    def list_suppressed(self, target: str) -> dict:
        """Return all suppressed and deferred assets for target."""
        from rek_state import state_graph

        suppressed = state_graph.get_subdomains_by_suppression_status(
            target, "suppressed"
        )
        deferred = state_graph.get_subdomains_by_suppression_status(
            target, "deferred"
        )
        merged = state_graph.get_subdomains_by_suppression_status(
            target, "merged"
        )

        return {
            "target":         target,
            "suppressed":     suppressed,
            "deferred":       deferred,
            "merged":         merged,
            "counts": {
                "suppressed": len(suppressed),
                "deferred":   len(deferred),
                "merged":     len(merged),
            },
        }

    # ------------------------------------------------------------------ #
    # Review: full suppression detail for a target                         #
    # ------------------------------------------------------------------ #

    def review(self, target: str) -> dict:
        """
        Return full suppression state for all subdomains: status, reason,
        confidence score, and source list.
        """
        from rek_state import state_graph
        from rek_source_trust import get_confidence

        snap = state_graph.get_target_state(target)
        assets = []
        for rec in snap.get("subdomains", []):
            source_list = _source_list(rec)
            assets.append({
                "fqdn":               rec["fqdn"],
                "suppression_status": rec.get("suppression_status", "candidate"),
                "suppression_reason": rec.get("suppression_reason"),
                "confidence_score":   rec.get("confidence_score", get_confidence(source_list)),
                "source_list":        source_list,
                "times_seen":         rec.get("times_seen", 1),
                "resolution_failures": rec.get("resolution_failures", 0),
                "last_seen":          rec.get("last_seen"),
            })

        # Sort: suppressed first, then deferred, then rest; alpha within groups
        _order = {"suppressed": 0, "merged": 1, "deferred": 2, "candidate": 3, "active": 4, "verified": 5}
        assets.sort(key=lambda a: (_order.get(a["suppression_status"], 9), a["fqdn"]))

        return {
            "target": target,
            "total":  len(assets),
            "assets": assets,
        }

    # ------------------------------------------------------------------ #
    # Restore a suppressed asset                                           #
    # ------------------------------------------------------------------ #

    def restore_asset(self, fqdn: str) -> dict:
        """
        Restore a suppressed or deferred asset to candidate status.

        Returns {"restored": bool, "fqdn": str, "previous_status": str}.
        """
        from rek_state import state_graph

        fqdn = fqdn.lower().strip()
        rec  = state_graph.get_subdomain(fqdn)
        if rec is None:
            _splog.warning("RESTORE_FAILED fqdn=%s reason=not_found", fqdn)
            return {"restored": False, "fqdn": fqdn, "error": "asset not found in state graph"}

        previous = rec.get("suppression_status", "candidate")
        state_graph.update_suppression(
            fqdn=fqdn,
            status="candidate",
            reason=None,
            confidence_score=rec.get("confidence_score", 0),
        )
        _splog.info(
            "ASSET_RESTORED fqdn=%s previous_status=%s", fqdn, previous,
        )
        return {"restored": True, "fqdn": fqdn, "previous_status": previous}


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

suppression_engine = FalsePositiveSuppressionEngine()

# ---------------------------------------------------------------------------
# CLI formatting helpers
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_DIM    = "\033[2m"

_STATUS_COLOUR = {
    "verified":   _GREEN,
    "active":     _GREEN,
    "candidate":  _CYAN,
    "deferred":   _YELLOW,
    "suppressed": _RED,
    "merged":     _DIM,
}


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if sys.stdout.isatty() else text


def _print_run(result: dict) -> None:
    target  = result["target"]
    summary = result["summary"]
    audit   = result["audit"]
    print()
    print(_c(f"REK Suppression Engine — {target}", _BOLD + _CYAN))
    print(f"  Total evaluated : {summary['total']}")
    print(f"  Verified        : {summary.get('verified', 0)}")
    print(f"  Active          : {summary.get('active', 0)}")
    print(f"  Candidate       : {summary.get('candidate', 0)}")
    print(f"  Deferred        : {summary.get('deferred', 0)}")
    print(f"  Suppressed      : {summary.get('suppressed', 0)}")
    print(f"  Merged          : {summary.get('merged', 0)}")
    print(f"  Unchanged       : {summary.get('unchanged', 0)}")
    print()
    if audit:
        print(_c("  Status changes:", _BOLD))
        for a in audit:
            colour = _STATUS_COLOUR.get(a["new_status"], _RESET)
            tag    = f"{a['old_status']} → {a['new_status']}"
            reason = f"  [{a['reason']}]" if a.get("reason") else ""
            print(_c(f"    {a['fqdn']:55s}  {tag}{reason}", colour))
    print(f"\n  Completed in {result['execution_time_seconds']}s\n")


def _print_list(result: dict) -> None:
    target = result["target"]
    print()
    print(_c(f"REK Suppressed Assets — {target}", _BOLD + _CYAN))

    for label, key in (("SUPPRESSED", "suppressed"), ("DEFERRED", "deferred"), ("MERGED", "merged")):
        items = result[key]
        colour = _RED if key == "suppressed" else (_YELLOW if key == "deferred" else _DIM)
        print(_c(f"\n  {label} ({len(items)})", colour))
        if not items:
            print("    (none)")
        for r in items:
            reason = r.get("suppression_reason", "")
            print(_c(f"    {r['fqdn']:55s}  [{reason}]", colour))
    print()


def _print_review(result: dict) -> None:
    target = result["target"]
    print()
    print(_c(f"REK Suppression Review — {target}  ({result['total']} assets)", _BOLD + _CYAN))
    print()
    for a in result["assets"]:
        colour = _STATUS_COLOUR.get(a["suppression_status"], _RESET)
        status = a["suppression_status"].upper()
        reason = f"  [{a['suppression_reason']}]" if a.get("suppression_reason") else ""
        print(_c(f"  [{status:10s}] conf={a['confidence_score']:2d}  {a['fqdn']}{reason}", colour))
        print(f"               sources={a['source_list']}  seen={a['times_seen']}  "
              f"res_fail={a['resolution_failures']}")
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="rek_suppression",
        description="REK False-Positive Suppression Engine",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_run = sub.add_parser("run", help="Evaluate assets and apply suppression rules")
    p_run.add_argument("target")
    p_run.add_argument("--json", action="store_true", dest="raw_json")

    p_list = sub.add_parser("list", help="Show suppressed and deferred assets")
    p_list.add_argument("target")
    p_list.add_argument("--json", action="store_true", dest="raw_json")

    p_review = sub.add_parser("review", help="Show suppression reasons and confidence details")
    p_review.add_argument("target")
    p_review.add_argument("--json", action="store_true", dest="raw_json")

    p_restore = sub.add_parser("restore", help="Restore a suppressed asset to candidate")
    p_restore.add_argument("asset", help="FQDN of the asset to restore")
    p_restore.add_argument("--json", action="store_true", dest="raw_json")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "run":
        result = suppression_engine.run_suppression(args.target)
        if args.raw_json:
            print(json.dumps(result, indent=2))
        else:
            _print_run(result)

    elif args.command == "list":
        result = suppression_engine.list_suppressed(args.target)
        if args.raw_json:
            print(json.dumps(result, indent=2))
        else:
            _print_list(result)

    elif args.command == "review":
        result = suppression_engine.review(args.target)
        if args.raw_json:
            print(json.dumps(result, indent=2))
        else:
            _print_review(result)

    elif args.command == "restore":
        result = suppression_engine.restore_asset(args.asset)
        if args.raw_json:
            print(json.dumps(result, indent=2))
        else:
            if result["restored"]:
                print(f"\n  Restored {result['fqdn']} "
                      f"(was: {result['previous_status']}) → candidate\n")
            else:
                print(f"\n  Failed to restore {result['fqdn']}: "
                      f"{result.get('error', 'unknown error')}\n")


if __name__ == "__main__":
    main()
