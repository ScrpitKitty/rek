#!/usr/bin/env python3
"""
rek_scheduler_state.py

Persistent scheduler state for the recon task queue.

Backed by state/recon_scheduler.json with atomic writes (temp file +
os.replace) and a threading.Lock so the module is safe for concurrent use.

Queue keys
----------
  pending_tasks   — tasks waiting to run
  running_tasks   — tasks currently executing
  completed_tasks — tasks that finished successfully
  skipped_tasks   — tasks that were suppressed (dup prevention, scope)
  deferred_tasks  — tasks held for later (dependency not yet met)
  failed_tasks    — tasks that exhausted retries
"""

import json
import logging
import logging.handlers
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_STATE_DIR  = os.path.join(_MODULE_DIR, "state")
_STATE_PATH = os.path.join(_STATE_DIR, "recon_scheduler.json")
_LOG_PATH   = os.path.join(_MODULE_DIR, "logs", "recon_scheduler.log")

# ---------------------------------------------------------------------------
# Logger — shared with planner and scheduler modules
# ---------------------------------------------------------------------------

_schlog = logging.getLogger("rek_scheduler")
_schlog.setLevel(logging.INFO)
_schlog.propagate = False

os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)
_sfh = logging.handlers.RotatingFileHandler(
    _LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_sfh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_schlog.addHandler(_sfh)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_QUEUE_KEYS = (
    "pending_tasks", "running_tasks", "completed_tasks",
    "skipped_tasks", "deferred_tasks", "failed_tasks",
)

_VALID_STATUSES = frozenset({
    "pending", "running", "completed", "skipped", "deferred", "failed",
})


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# SchedulerState
# ---------------------------------------------------------------------------

class SchedulerState:
    """Thread-safe persistent scheduler state."""

    def __init__(self, state_path: str = _STATE_PATH):
        self._path = state_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(state_path), exist_ok=True)
        self._state = self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> dict:
        if os.path.exists(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for key in _QUEUE_KEYS:
                    data.setdefault(key, [])
                data.setdefault("last_scheduler_run", None)
                return data
            except (json.JSONDecodeError, OSError) as exc:
                _schlog.warning("Scheduler state unreadable (%s) — starting fresh.", exc)
        state = {k: [] for k in _QUEUE_KEYS}
        state["last_scheduler_run"] = None
        return state

    def _flush(self) -> None:
        """Atomic write via temp file + os.replace."""
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._state, f, indent=2)
        os.replace(tmp, self._path)

    # ------------------------------------------------------------------
    # Task management
    # ------------------------------------------------------------------

    def add_task(self, task: dict) -> None:
        """Append a task to pending_tasks."""
        with self._lock:
            self._state["pending_tasks"].append(task)
            _schlog.info(
                "TASK_CREATED task_id=%s target=%s tool=%s priority=%d",
                task["task_id"], task["target"],
                task["tool_or_playbook"], task["priority"],
            )
            self._flush()

    def update_task(self, task_id: str, **fields) -> bool:
        """Update arbitrary fields on a task in any queue. Returns True if found."""
        with self._lock:
            for key in _QUEUE_KEYS:
                for task in self._state[key]:
                    if task["task_id"] == task_id:
                        task.update(fields)
                        self._flush()
                        return True
        return False

    def move_task(self, task_id: str, new_status: str) -> Optional[dict]:
        """
        Remove task from its current queue and place it into the queue
        matching new_status. Returns the moved task or None if not found.
        """
        if new_status not in _VALID_STATUSES:
            raise ValueError(f"Invalid status: {new_status!r}")
        dest_key = f"{new_status}_tasks"
        with self._lock:
            for src_key in _QUEUE_KEYS:
                for i, task in enumerate(self._state[src_key]):
                    if task["task_id"] == task_id:
                        task = self._state[src_key].pop(i)
                        task["status"] = new_status
                        self._state[dest_key].append(task)
                        self._flush()
                        return task
        return None

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_pending(self, target: Optional[str] = None) -> List[dict]:
        """Return pending tasks sorted by priority desc, created_at asc."""
        with self._lock:
            tasks = list(self._state["pending_tasks"])
        if target:
            target = target.lower().strip()
            tasks = [t for t in tasks if t["target"] == target]
        tasks.sort(key=lambda t: (-t["priority"], t["created_at"]))
        return tasks

    def get_all_active(self, target: Optional[str] = None) -> List[dict]:
        """Return pending + running tasks."""
        with self._lock:
            tasks = (
                list(self._state["pending_tasks"]) +
                list(self._state["running_tasks"])
            )
        if target:
            target = target.lower().strip()
            tasks = [t for t in tasks if t["target"] == target]
        return tasks

    def get_completed(
        self,
        target: Optional[str] = None,
        tool: Optional[str] = None,
    ) -> List[dict]:
        """Return completed tasks, optionally filtered."""
        with self._lock:
            tasks = list(self._state["completed_tasks"])
        if target:
            target = target.lower().strip()
            tasks = [t for t in tasks if t["target"] == target]
        if tool:
            tasks = [t for t in tasks if t["tool_or_playbook"] == tool]
        return tasks

    def has_recent_task(
        self,
        target: str,
        tool: str,
        window_hours: int = 24,
        host: Optional[str] = None,
    ) -> bool:
        """
        Return True if a matching task exists in pending, running, or completed
        within the past window_hours.

        If host is provided, tasks must also match the 'host' field.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        target = target.lower().strip()
        with self._lock:
            for key in ("pending_tasks", "running_tasks", "completed_tasks"):
                for t in self._state[key]:
                    if t["target"] != target or t["tool_or_playbook"] != tool:
                        continue
                    if host and t.get("host", "") != host:
                        continue
                    try:
                        created = datetime.fromisoformat(t["created_at"])
                        if created >= cutoff:
                            return True
                    except (ValueError, KeyError):
                        pass
        return False

    def get_completed_ids(self) -> set:
        """Return the set of task_ids in completed_tasks."""
        with self._lock:
            return {t["task_id"] for t in self._state["completed_tasks"]}

    def get_summary(self) -> dict:
        with self._lock:
            return {
                "pending":   len(self._state["pending_tasks"]),
                "running":   len(self._state["running_tasks"]),
                "completed": len(self._state["completed_tasks"]),
                "skipped":   len(self._state["skipped_tasks"]),
                "deferred":  len(self._state["deferred_tasks"]),
                "failed":    len(self._state["failed_tasks"]),
                "last_run":  self._state["last_scheduler_run"],
            }

    def flush_pending(self) -> int:
        """Clear all pending tasks. Returns count removed."""
        with self._lock:
            count = len(self._state["pending_tasks"])
            self._state["pending_tasks"] = []
            self._flush()
        _schlog.info("QUEUE_FLUSHED count=%d", count)
        return count

    def touch_last_run(self) -> None:
        with self._lock:
            self._state["last_scheduler_run"] = _ts()
            self._flush()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

scheduler_state = SchedulerState()
