#!/usr/bin/env python3
"""
rek_planner.py

Rule-based recon task planner.

Inspects the recon state graph and applies six deterministic planning rules
to produce a list of tasks ready for the scheduler queue. No AI dependency.

Planning rules
--------------
  Rule 1 — new root target        → enqueue passive discovery
  Rule 2 — new subdomain          → enqueue port scan (active recon)
  Rule 3 — high-priority asset    → extended endpoint enum + analysis refresh
  Rule 4 — stale asset            → lightweight passive refresh
  Rule 5 — duplicate prevention   → skip, log reason (applied inline)
  Rule 6 — scope enforcement      → reject, log reason (applied inline)

Policy defaults
---------------
  stale_days              : 7
  duplicate_window_hours  : 24
  high_threshold          : 10
  medium_threshold        : 5
  max_pending             : 100
"""

import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Set

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _MODULE_DIR)

_plog = logging.getLogger("rek_scheduler")  # shares the scheduler log file

# ---------------------------------------------------------------------------
# Policy defaults
# ---------------------------------------------------------------------------

_DEFAULT_STALE_DAYS        = 7
_DEFAULT_DUPLICATE_HOURS   = 24
_DEFAULT_HIGH_THRESHOLD    = 10
_DEFAULT_MEDIUM_THRESHOLD  = 5
_DEFAULT_MAX_PENDING       = 100

_PASSIVE_TOOLS = frozenset({"expand_target"})
_ANALYSIS_TYPES = frozenset({"analysis", "aggregation"})

# HTTP ports used to decide if endpoint scanning is warranted
_HTTP_PORTS = frozenset({80, 443, 8000, 8080, 8443, 8888})


# ---------------------------------------------------------------------------
# ReconPlanner
# ---------------------------------------------------------------------------

class ReconPlanner:
    """
    Deterministic recon task planner.

    plan_target() is the primary entry point — it applies all six rules and
    returns a deduplicated, priority-sorted list of task dicts.
    """

    def __init__(
        self,
        scope_roots: Optional[List[str]] = None,
        mode: str = "standard",
        stale_days: int = _DEFAULT_STALE_DAYS,
        duplicate_window_hours: int = _DEFAULT_DUPLICATE_HOURS,
        high_threshold: int = _DEFAULT_HIGH_THRESHOLD,
        medium_threshold: int = _DEFAULT_MEDIUM_THRESHOLD,
        max_pending: int = _DEFAULT_MAX_PENDING,
        passive_only: bool = False,
    ):
        self.scope_roots            = [r.lower().strip() for r in (scope_roots or [])]
        self.mode                   = mode
        self.stale_days             = stale_days
        self.duplicate_window_hours = duplicate_window_hours
        self.high_threshold         = high_threshold
        self.medium_threshold       = medium_threshold
        self.max_pending            = max_pending
        self.passive_only           = passive_only or (mode == "passive_only")

    # ------------------------------------------------------------------
    # Rule 6 helper: scope enforcement
    # ------------------------------------------------------------------

    def _in_scope(self, host: str) -> bool:
        """Return True if host falls within an allowed scope root."""
        if not self.scope_roots:
            return True
        host = host.lower().strip()
        return any(
            host == root or host.endswith("." + root)
            for root in self.scope_roots
        )

    # ------------------------------------------------------------------
    # Rule 4 helper: staleness check
    # ------------------------------------------------------------------

    def _is_stale(self, last_seen_iso: Optional[str]) -> bool:
        if not last_seen_iso:
            return True
        try:
            last = datetime.fromisoformat(last_seen_iso)
            return (datetime.now(timezone.utc) - last) > timedelta(days=self.stale_days)
        except (ValueError, TypeError):
            return True

    # ------------------------------------------------------------------
    # Rule 5 helper: duplicate prevention
    # ------------------------------------------------------------------

    def _is_duplicate(
        self,
        target: str,
        tool: str,
        sched_state,
        host: Optional[str] = None,
    ) -> bool:
        dupe = sched_state.has_recent_task(
            target, tool, self.duplicate_window_hours, host=host
        )
        if dupe:
            _plog.info(
                "TASK_SKIPPED rule=5 target=%s tool=%s host=%s reason=duplicate",
                target, tool, host or "",
            )
        return dupe

    # ------------------------------------------------------------------
    # Rule 1: new root target
    # ------------------------------------------------------------------

    def _rule_1_new_root_target(
        self,
        target: str,
        snap: dict,
        sched_state,
        org: str,
    ) -> List[dict]:
        """
        If the target has no discovery history, schedule passive expansion first.
        Passive sources: CT logs, passive DNS (HackerTarget + ThreatMiner), SAN.
        ASN expansion is added when an org name is provided.
        """
        from rek_task_queue import make_task, calculate_priority

        # Already has subdomains or technology info — not a fresh target
        if snap.get("subdomains") or snap.get("technologies"):
            return []

        if self._is_duplicate(target, "expand_target", sched_state):
            return []

        sources = ["ct", "hackertarget", "threatminer", "san"]
        if org:
            sources.append("asn")

        pri = calculate_priority(is_new=True, is_root=True, is_passive_nohistory=True)
        task = make_task(
            target=target,
            task_type="passive_discovery",
            tool_or_playbook="expand_target",
            reason="Rule 1: new root target — passive expansion scheduled first",
            priority=pri,
            extra={"sources": sources, "org": org},
        )
        _plog.info("TASK_PLANNED rule=1 target=%s tool=expand_target", target)
        return [task]

    # ------------------------------------------------------------------
    # Rule 2: new subdomain discovered
    # ------------------------------------------------------------------

    def _rule_2_new_subdomain(
        self,
        target: str,
        snap: dict,
        sched_state,
    ) -> List[dict]:
        """
        For each subdomain with no known open ports, schedule a port scan.
        Skips passive_only mode. Applies scope and duplicate guards per host.
        """
        from rek_task_queue import make_task, calculate_priority
        from rek_state import state_graph

        if self.passive_only:
            return []

        tasks = []
        for sub in snap.get("subdomains", []):
            host = sub["fqdn"]

            # Rule 6: scope enforcement
            if not self._in_scope(host):
                _plog.info(
                    "TASK_SKIPPED rule=6 target=%s host=%s reason=out_of_scope",
                    target, host,
                )
                continue

            # Suppression gate — respect false-positive suppression decisions.
            # suppressed/merged: never schedule.
            # deferred: only schedule in non-standard modes (e.g. review or deep-recon).
            sup_status = sub.get("suppression_status", "candidate")
            if sup_status in ("suppressed", "merged"):
                _plog.info(
                    "TASK_SKIPPED suppression target=%s host=%s status=%s",
                    target, host, sup_status,
                )
                continue
            if sup_status == "deferred" and self.mode in ("standard", "passive_only"):
                _plog.info(
                    "TASK_SKIPPED suppression target=%s host=%s status=deferred "
                    "(mode=%s requires review or immediate_execute to schedule deferred)",
                    target, host, self.mode,
                )
                continue

            # Only schedule if no open ports known for this host
            if state_graph.get_open_ports(host):
                continue

            # Rule 5: per-host duplicate prevention
            if self._is_duplicate(target, "run_port_scan", sched_state, host=host):
                continue

            pri = calculate_priority(is_new=True)
            tasks.append(make_task(
                target=target,
                task_type="active_recon",
                tool_or_playbook="run_port_scan",
                reason=f"Rule 2: new subdomain {host} — port scan",
                priority=pri,
                extra={"host": host},
            ))
            _plog.info("TASK_PLANNED rule=2 target=%s host=%s tool=run_port_scan",
                       target, host)

        return tasks

    # ------------------------------------------------------------------
    # Rule 3: high-priority asset follow-up
    # ------------------------------------------------------------------

    def _rule_3_interesting_asset(
        self,
        target: str,
        sched_state,
    ) -> List[dict]:
        """
        High-priority assets (score >= high_threshold) receive:
          - extended endpoint enumeration (if HTTP port detected)
          - analysis / reprioritization refresh
        """
        from rek_task_queue import make_task, calculate_priority
        from rek_intel import intel_engine
        from rek_state import state_graph

        if self.passive_only:
            return []

        result = intel_engine.analyze_target(target)
        tasks  = []

        for finding in result.get("high_priority", []):
            host  = finding["host"]
            score = finding["score"]

            if not self._in_scope(host):
                continue

            # Endpoint enum only when HTTP-capable ports are present
            ports      = state_graph.get_open_ports(host)
            http_ports = [p for p in ports if p in _HTTP_PORTS]
            if http_ports and not self._is_duplicate(
                target, "run_endpoint_scan", sched_state, host=host
            ):
                pri = calculate_priority(intel_score=score)
                tasks.append(make_task(
                    target=target,
                    task_type="active_recon",
                    tool_or_playbook="run_endpoint_scan",
                    reason=(
                        f"Rule 3: high-priority host {host} score={score} "
                        "— extended endpoint enumeration"
                    ),
                    priority=pri,
                    extra={"host": host},
                ))
                _plog.info(
                    "TASK_PLANNED rule=3 target=%s host=%s tool=run_endpoint_scan",
                    target, host,
                )

        # Analysis refresh — one per target, not per host
        if result.get("high_priority") and not self._is_duplicate(
            target, "analyze_target", sched_state
        ):
            top_score = result["high_priority"][0]["score"]
            pri = calculate_priority(intel_score=top_score, is_root=True)
            tasks.append(make_task(
                target=target,
                task_type="analysis",
                tool_or_playbook="analyze_target",
                reason="Rule 3: high-priority findings — reprioritization refresh",
                priority=pri,
            ))
            _plog.info("TASK_PLANNED rule=3 target=%s tool=analyze_target", target)

        return tasks

    # ------------------------------------------------------------------
    # Rule 4: stale asset refresh
    # ------------------------------------------------------------------

    def _rule_4_stale_asset(
        self,
        target: str,
        snap: dict,
        sched_state,
    ) -> List[dict]:
        """
        If the target hasn't been scanned within stale_days, schedule a
        lightweight passive refresh. Heavy scans are NOT re-queued unless
        explicitly configured (constraint from baton spec).
        """
        from rek_task_queue import make_task, calculate_priority

        target_rec   = snap.get("target", {})
        last_scanned = target_rec.get("last_scanned")

        if not self._is_stale(last_scanned):
            return []

        if self._is_duplicate(target, "expand_target", sched_state):
            return []

        pri = calculate_priority(is_stale=True)
        task = make_task(
            target=target,
            task_type="passive_discovery",
            tool_or_playbook="expand_target",
            reason=(
                f"Rule 4: stale asset (last_scanned={last_scanned}) "
                "— lightweight passive refresh"
            ),
            priority=pri,
            extra={"sources": ["ct", "hackertarget", "threatminer"]},
        )
        _plog.info("TASK_PLANNED rule=4 target=%s tool=expand_target (stale)", target)
        return [task]

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    def plan_target(
        self,
        target: str,
        org: str = "",
        sched_state=None,
    ) -> List[dict]:
        """
        Apply all planning rules to target and return a deduplicated,
        priority-sorted list of tasks ready for enqueueing.

        sched_state defaults to the module-level singleton if not provided.
        """
        if sched_state is None:
            from rek_scheduler_state import scheduler_state as sched_state

        from rek_state import state_graph

        target = target.lower().strip()

        # Domain gate: root domain must be approved before any tasks are planned.
        from rek_domain_gate import domain_gate
        gate_allowed = domain_gate.domain_safety_gate(
            target, discovered_from="planner", discovery_method="plan_target"
        )
        if not gate_allowed:
            gate_status = domain_gate.get_status(target)
            _plog.info(
                "PLAN_REJECTED target=%s reason=domain_gate root=%s status=%s",
                target, gate_status.get("root", target), gate_status.get("status", "pending"),
            )
            return []

        # Rule 6: root-level scope enforcement
        if self.scope_roots and not self._in_scope(target):
            _plog.info("PLAN_REJECTED target=%s reason=out_of_scope", target)
            return []

        snap = state_graph.get_target_state(target)

        tasks: List[dict] = []
        tasks.extend(self._rule_1_new_root_target(target, snap, sched_state, org))
        tasks.extend(self._rule_2_new_subdomain(target, snap, sched_state))
        tasks.extend(self._rule_3_interesting_asset(target, sched_state))
        tasks.extend(self._rule_4_stale_asset(target, snap, sched_state))

        # Passive-only mode: drop tasks that require active tools
        if self.passive_only:
            before = len(tasks)
            tasks = [
                t for t in tasks
                if t["tool_or_playbook"] in _PASSIVE_TOOLS
                or t["task_type"] in _ANALYSIS_TYPES
            ]
            removed = before - len(tasks)
            if removed:
                _plog.info(
                    "PASSIVE_FILTER target=%s removed=%d active_tasks",
                    target, removed,
                )

        # Deduplicate within the newly planned batch (target + tool + host)
        seen:   Set[str]  = set()
        unique: List[dict] = []
        for task in tasks:
            key = f"{task['target']}:{task['tool_or_playbook']}:{task.get('host', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(task)

        # Final sort: priority desc, created_at asc
        unique.sort(key=lambda t: (-t["priority"], t["created_at"]))

        _plog.info("PLAN_COMPLETED target=%s tasks=%d", target, len(unique))
        return unique


# ---------------------------------------------------------------------------
# Module-level singleton (no scope restriction by default)
# ---------------------------------------------------------------------------

recon_planner = ReconPlanner()
