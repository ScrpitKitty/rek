#!/usr/bin/env python3
"""
rek_task_queue.py

Task creation factory, priority calculation, and dependency resolution
for the recon scheduler.

Priority addend table (additive — no AI, fully deterministic)
-------------------------------------------------------------
  new asset                  : +5
  high-interest (score >= 10): +5
  medium-interest (score >= 5): +3
  root target                : +2
  passive task, no history   : +2
  stale refresh              : +1
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional

# ---------------------------------------------------------------------------
# Priority constants (mirrors baton spec)
# ---------------------------------------------------------------------------

_PRI_NEW_ASSET          = 5
_PRI_HIGH_INTEREST      = 5
_PRI_MED_INTEREST       = 3
_PRI_ROOT_TARGET        = 2
_PRI_PASSIVE_NOHISTORY  = 2
_PRI_STALE_REFRESH      = 1

HIGH_PRIORITY_THRESHOLD   = 10
MEDIUM_PRIORITY_THRESHOLD = 5


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Task factory
# ---------------------------------------------------------------------------

def make_task(
    target: str,
    task_type: str,
    tool_or_playbook: str,
    reason: str,
    priority: int = 0,
    dependencies: Optional[List[str]] = None,
    extra: Optional[dict] = None,
) -> dict:
    """
    Build a task dict conforming to the scheduler task schema.

    Parameters
    ----------
    target           : root domain being investigated
    task_type        : passive_discovery | active_recon | aggregation | analysis
    tool_or_playbook : expand_target | run_port_scan | run_endpoint_scan | analyze_target
    reason           : human-readable planning rule rationale
    priority         : pre-computed additive priority score
    dependencies     : list of task_ids that must complete before this runs
    extra            : optional fields to merge in (e.g. host, sources, org)
    """
    task = {
        "task_id":          str(uuid.uuid4()),
        "target":           target.lower().strip(),
        "task_type":        task_type,
        "tool_or_playbook": tool_or_playbook,
        "reason":           reason,
        "priority":         priority,
        "created_at":       _ts(),
        "scheduled_at":     None,
        "completed_at":     None,
        "status":           "pending",
        "dependencies":     dependencies or [],
        "retries":          0,
        "result":           None,
    }
    if extra:
        task.update(extra)
    return task


# ---------------------------------------------------------------------------
# Priority calculator
# ---------------------------------------------------------------------------

def calculate_priority(
    base: int = 0,
    is_new: bool = False,
    intel_score: int = 0,
    is_root: bool = False,
    is_stale: bool = False,
    is_passive_nohistory: bool = False,
) -> int:
    """
    Deterministic additive priority calculation.

    All conditions are evaluated independently and summed — no branching
    or early-exit that could produce non-deterministic results.
    """
    p = base
    if is_new:
        p += _PRI_NEW_ASSET
    if intel_score >= HIGH_PRIORITY_THRESHOLD:
        p += _PRI_HIGH_INTEREST
    elif intel_score >= MEDIUM_PRIORITY_THRESHOLD:
        p += _PRI_MED_INTEREST
    if is_root:
        p += _PRI_ROOT_TARGET
    if is_stale:
        p += _PRI_STALE_REFRESH
    if is_passive_nohistory:
        p += _PRI_PASSIVE_NOHISTORY
    return p


# ---------------------------------------------------------------------------
# Dependency resolver
# ---------------------------------------------------------------------------

def get_ready_tasks(
    pending: List[dict],
    completed_ids: set,
) -> List[dict]:
    """
    Filter pending to tasks whose full dependency set is satisfied
    (all dependency task_ids present in completed_ids).

    Input list must already be sorted in execution-order preference
    (priority desc, created_at asc).
    """
    return [
        t for t in pending
        if all(dep in completed_ids for dep in t.get("dependencies", []))
    ]
