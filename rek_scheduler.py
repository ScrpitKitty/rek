#!/usr/bin/env python3
"""
rek_scheduler.py

Recon scheduler — orchestrates task planning and execution.

Scheduler modes
---------------
  standard          — passive expansion + active recon (default)
  passive_only      — passive discovery and analysis tasks only
  review_queue_only — generate task queue without executing
  immediate_execute — plan and execute eligible tasks in one call

Execution pipeline (per task)
------------------------------
  1. Check dependencies (all dependency task_ids must be in completed set)
  2. Mark task running
  3. Execute via _execute_task()
  4. Mark completed or failed (retry once on transient errors)
  5. Trigger analysis refresh if new findings exist

CLI usage
---------
  python rek_scheduler.py plan   <target> [--org STR] [--mode MODE] [--scope ROOT...] [--no-enqueue] [--json]
  python rek_scheduler.py run    [<target>] [--limit N] [--mode MODE] [--scope ROOT...] [--json]
  python rek_scheduler.py status [--json]
  python rek_scheduler.py queue  [<target>] [--json]
  python rek_scheduler.py flush  [--json]
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import List, Optional

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _MODULE_DIR)

_schlog = logging.getLogger("rek_scheduler")  # shared with state and planner modules

_MAX_RETRIES = 1
_VALID_MODES = frozenset({
    "standard", "passive_only", "review_queue_only", "immediate_execute",
})


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Task executor
# ---------------------------------------------------------------------------

def _execute_task(task: dict) -> dict:
    """
    Execute a single scheduler task synchronously.

    Returns {"success": bool, "output": str, "error": str}.

    Tool routing
    ------------
    expand_target     → rek_expand.expansion_engine.expand_all()
    analyze_target    → rek_intel.intel_engine.analyze_target()
    run_port_scan     → naabu subprocess; results written to state graph
    run_endpoint_scan → katana subprocess; results written to state graph
    """
    tool   = task["tool_or_playbook"]
    target = task["target"]
    host   = task.get("host", target)

    # ------------------------------------------------------------------
    # Scope gate — block active recon against out-of-scope assets.
    # Passive tools (expand_target, analyze_target) are exempt because
    # they query third-party databases, not the target infrastructure.
    # ------------------------------------------------------------------
    _ACTIVE_TOOLS = frozenset({"run_port_scan", "run_endpoint_scan"})
    if tool in _ACTIVE_TOOLS:
        from rek_scope import scope_guard
        scope_result = scope_guard.in_scope(host)
        if not scope_result["allowed"]:
            _schlog.info(
                "SCOPE_BLOCKED_EXECUTION task_id=%s host=%s reason=%s action=blocked",
                task["task_id"], host, scope_result["scope_reason"],
            )
            return {
                "success": False,
                "output":  "",
                "error":   f"out_of_scope: {host} ({scope_result['scope_reason']})",
            }

    try:
        # ---- Passive expansion -------------------------------------------
        if tool == "expand_target":
            from rek_expand import expansion_engine
            sources = task.get("sources") or None
            org     = task.get("org", "")
            result  = expansion_engine.expand_all(target, org, sources)
            return {
                "success": True,
                "output":  json.dumps(result),
                "error":   "",
            }

        # ---- Intelligence analysis ----------------------------------------
        elif tool == "analyze_target":
            from rek_intel import intel_engine
            result = intel_engine.analyze_target(target)
            return {
                "success": True,
                "output":  json.dumps({
                    "hosts_analyzed": result["hosts_analyzed"],
                    "high_count":     len(result["high_priority"]),
                    "medium_count":   len(result["medium_priority"]),
                    "low_count":      len(result["low_priority"]),
                }),
                "error": "",
            }

        # ---- Port scan (naabu) -------------------------------------------
        elif tool == "run_port_scan":
            tools_dir = os.path.join(_MODULE_DIR, "tools")
            naabu     = os.path.join(tools_dir, "naabu")
            if not os.path.isfile(naabu):
                naabu = "naabu"  # fall back to PATH

            cmd  = [naabu, "-host", host, "-silent", "-json"]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
            )
            if proc.returncode != 0 and not proc.stdout.strip():
                return {"success": False, "output": "", "error": proc.stderr[:500]}

            from rek_state import state_graph
            ports_found = 0
            for line in proc.stdout.splitlines():
                try:
                    rec  = json.loads(line)
                    port = rec.get("port")
                    if port:
                        state_graph.upsert_service(host, int(port))
                        ports_found += 1
                except (json.JSONDecodeError, ValueError):
                    pass

            return {
                "success": True,
                "output":  json.dumps({"host": host, "ports_found": ports_found}),
                "error":   "",
            }

        # ---- Endpoint scan (katana) ---------------------------------------
        elif tool == "run_endpoint_scan":
            tools_dir = os.path.join(_MODULE_DIR, "tools")
            katana    = os.path.join(tools_dir, "katana")
            if not os.path.isfile(katana):
                katana = "katana"

            from rek_state import state_graph
            ports = state_graph.get_open_ports(host) or [80, 443]
            urls  = [
                f"http{'s' if p in (443, 8443) else ''}://{host}"
                + (f":{p}" if p not in (80, 443) else "")
                for p in ports
                if p in (80, 443, 8000, 8080, 8443, 8888)
            ]
            if not urls:
                urls = [f"http://{host}"]

            endpoints_found = 0
            for url in urls[:4]:  # cap to prevent runaway scans
                cmd  = [katana, "-u", url, "-silent", "-jc", "-d", "2"]
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=180,
                )
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("http"):
                        state_graph.upsert_endpoint(line)
                        endpoints_found += 1

            return {
                "success": True,
                "output":  json.dumps({"host": host, "endpoints_found": endpoints_found}),
                "error":   "",
            }

        else:
            return {
                "success": False,
                "output":  "",
                "error":   f"No executor registered for tool: {tool!r}",
            }

    except FileNotFoundError as exc:
        return {"success": False, "output": "", "error": f"Tool not found: {exc}"}
    except subprocess.TimeoutExpired:
        return {"success": False, "output": "", "error": "Subprocess timeout"}
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "output": "", "error": str(exc)}


# ---------------------------------------------------------------------------
# ReconScheduler
# ---------------------------------------------------------------------------

class ReconScheduler:
    """
    Orchestrates task planning and execution.

    Instantiate with a mode and optional scope_roots. All public methods
    are synchronous; the MCP wrapper calls them via run_in_executor.
    """

    def __init__(
        self,
        mode: str = "standard",
        scope_roots: Optional[List[str]] = None,
    ):
        self.mode        = mode if mode in _VALID_MODES else "standard"
        self.scope_roots = scope_roots or []

    def _make_planner(self, mode: Optional[str] = None, org: str = ""):
        from rek_planner import ReconPlanner
        m = mode or self.mode
        return ReconPlanner(
            scope_roots=self.scope_roots,
            mode=m,
            passive_only=(m == "passive_only"),
        )

    # ------------------------------------------------------------------
    # Plan
    # ------------------------------------------------------------------

    def plan(
        self,
        target: str,
        org: str = "",
        mode: Optional[str] = None,
        enqueue: bool = True,
    ) -> List[dict]:
        """
        Generate tasks for target via the planner and optionally enqueue them.

        Returns the list of newly created (not previously queued) tasks.
        """
        from rek_scheduler_state import scheduler_state
        from rek_state import state_graph

        _schlog.info("SCHEDULER_STARTED target=%s mode=%s", target, mode or self.mode)

        state_graph.upsert_target(target)

        planner = self._make_planner(mode, org)
        tasks   = planner.plan_target(target, org=org, sched_state=scheduler_state)

        # Cap to available pending capacity
        pending_count = scheduler_state.get_summary()["pending"]
        available     = max(0, planner.max_pending - pending_count)
        tasks         = tasks[:available]

        if enqueue:
            for task in tasks:
                scheduler_state.add_task(task)

        _schlog.info(
            "SCHEDULER_PLANNED target=%s tasks_created=%d enqueued=%s",
            target, len(tasks), enqueue,
        )
        return tasks

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(
        self,
        target: Optional[str] = None,
        limit: int = 10,
        mode: Optional[str] = None,
    ) -> dict:
        """
        Execute up to `limit` eligible pending tasks.

        Eligible = pending + dependencies fully satisfied.
        Returns a summary dict.
        """
        from rek_scheduler_state import scheduler_state
        from rek_task_queue import get_ready_tasks

        effective_mode = mode or self.mode

        # review_queue_only — return queue without executing
        if effective_mode == "review_queue_only":
            pending = scheduler_state.get_pending(target)
            return {
                "mode":    effective_mode,
                "message": "review_queue_only: tasks not executed",
                "queued":  len(pending),
                "tasks":   pending[:limit],
            }

        _schlog.info(
            "SCHEDULER_RUN_STARTED target=%s limit=%d mode=%s",
            target or "*", limit, effective_mode,
        )
        scheduler_state.touch_last_run()

        completed_ids = scheduler_state.get_completed_ids()

        pending = scheduler_state.get_pending(target)
        ready   = get_ready_tasks(pending, completed_ids)

        # passive_only: restrict to passive + analysis tools only
        if effective_mode == "passive_only":
            ready = [
                t for t in ready
                if t["tool_or_playbook"] in ("expand_target", "analyze_target")
            ]

        to_run  = ready[:limit]
        ran     = []
        failed  = []

        for task in to_run:
            task_id = task["task_id"]
            _schlog.info(
                "TASK_STARTED task_id=%s target=%s tool=%s",
                task_id, task["target"], task["tool_or_playbook"],
            )
            scheduler_state.move_task(task_id, "running")
            scheduler_state.update_task(task_id, scheduled_at=_ts())

            exec_result = _execute_task(task)

            if exec_result["success"]:
                scheduler_state.move_task(task_id, "completed")
                scheduler_state.update_task(
                    task_id,
                    completed_at=_ts(),
                    result={"output": exec_result["output"]},
                )
                _schlog.info("TASK_COMPLETED task_id=%s", task_id)
                ran.append(task_id)
            else:
                retries = task.get("retries", 0)
                if retries < _MAX_RETRIES:
                    scheduler_state.move_task(task_id, "pending")
                    scheduler_state.update_task(
                        task_id, retries=retries + 1, status="pending",
                    )
                    _schlog.info(
                        "TASK_RETRY task_id=%s attempt=%d error=%s",
                        task_id, retries + 1, exec_result["error"][:120],
                    )
                else:
                    scheduler_state.move_task(task_id, "failed")
                    scheduler_state.update_task(
                        task_id,
                        result={"error": exec_result["error"]},
                    )
                    _schlog.info(
                        "TASK_FAILED task_id=%s error=%s",
                        task_id, exec_result["error"][:120],
                    )
                    failed.append(task_id)

        _schlog.info(
            "SCHEDULER_FINISHED ran=%d failed=%d", len(ran), len(failed),
        )
        return {
            "mode":          effective_mode,
            "tasks_run":     len(ran),
            "tasks_failed":  len(failed),
            "completed_ids": ran,
            "failed_ids":    failed,
        }

    # ------------------------------------------------------------------
    # Status / queue / flush
    # ------------------------------------------------------------------

    def status(self) -> dict:
        from rek_scheduler_state import scheduler_state
        return scheduler_state.get_summary()

    def queue(self, target: Optional[str] = None) -> List[dict]:
        from rek_scheduler_state import scheduler_state
        return scheduler_state.get_pending(target)

    def flush(self) -> int:
        from rek_scheduler_state import scheduler_state
        return scheduler_state.flush_pending()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

recon_scheduler = ReconScheduler()

# ---------------------------------------------------------------------------
# CLI formatting helpers
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if sys.stdout.isatty() else text


_STATUS_COLOUR = {
    "pending":   _YELLOW,
    "running":   _CYAN,
    "completed": _GREEN,
    "failed":    _RED,
    "skipped":   _RESET,
    "deferred":  _RESET,
}


def _print_plan(tasks: List[dict]) -> None:
    print()
    print(_c(f"REK Scheduler — Planned Tasks ({len(tasks)})", _BOLD + _CYAN))
    print()
    if not tasks:
        print("  No new tasks planned (queue is up to date).")
        print()
        return
    for t in tasks:
        colour = _STATUS_COLOUR.get(t["status"], _RESET)
        host   = t.get("host", t["target"])
        print(_c(f"  [{t['priority']:3d}] {t['tool_or_playbook']:28s}  {host}", colour))
        print(f"        type   : {t['task_type']}")
        print(f"        reason : {t['reason']}")
        if t.get("dependencies"):
            print(f"        deps   : {t['dependencies']}")
    print()


def _print_run(result: dict) -> None:
    print()
    print(_c("REK Scheduler — Run Summary", _BOLD + _CYAN))
    print(f"  Mode         : {result['mode']}")
    print(f"  Tasks run    : {result['tasks_run']}")
    print(f"  Tasks failed : {result['tasks_failed']}")
    if result.get("message"):
        print(f"  Note         : {result['message']}")
    if result.get("queued"):
        print(f"  Queued       : {result['queued']}")
    print()


def _print_status(summary: dict) -> None:
    print()
    print(_c("REK Scheduler — Status", _BOLD + _CYAN))
    for key, val in summary.items():
        print(f"  {key:20s}: {val}")
    print()


def _print_queue(tasks: List[dict]) -> None:
    print()
    print(_c(f"REK Scheduler — Pending Queue ({len(tasks)})", _BOLD + _CYAN))
    print()
    if not tasks:
        print("  Queue is empty.")
        print()
        return
    for t in tasks:
        colour = _STATUS_COLOUR.get(t["status"], _RESET)
        host   = t.get("host", t["target"])
        print(_c(f"  [{t['priority']:3d}] {t['tool_or_playbook']:28s}  {host}", colour))
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="rek_scheduler",
        description="REK Recon Scheduler — deterministic scan planning and execution",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ---- plan ----
    p_plan = sub.add_parser("plan", help="Plan recon tasks for a target")
    p_plan.add_argument("target")
    p_plan.add_argument("--org",   default="", help="Organisation name for ASN lookup")
    p_plan.add_argument("--mode",  default="standard", choices=sorted(_VALID_MODES))
    p_plan.add_argument("--scope", nargs="+", default=[],
                        help="Allowed scope roots (default: target itself)")
    p_plan.add_argument("--no-enqueue", action="store_true",
                        help="Preview tasks without adding to queue")
    p_plan.add_argument("--json", action="store_true", dest="raw_json")

    # ---- run ----
    p_run = sub.add_parser("run", help="Execute pending scheduled tasks")
    p_run.add_argument("target", nargs="?", default=None,
                       help="Filter by target (default: all targets)")
    p_run.add_argument("--limit", type=int, default=10,
                       help="Max tasks to execute (default: 10)")
    p_run.add_argument("--mode",  default="standard", choices=sorted(_VALID_MODES))
    p_run.add_argument("--scope", nargs="+", default=[])
    p_run.add_argument("--json", action="store_true", dest="raw_json")

    # ---- status ----
    p_status = sub.add_parser("status", help="Show scheduler queue summary")
    p_status.add_argument("--json", action="store_true", dest="raw_json")

    # ---- queue ----
    p_queue = sub.add_parser("queue", help="List pending tasks")
    p_queue.add_argument("target", nargs="?", default=None)
    p_queue.add_argument("--json", action="store_true", dest="raw_json")

    # ---- flush ----
    p_flush = sub.add_parser("flush", help="Clear all pending tasks")
    p_flush.add_argument("--json", action="store_true", dest="raw_json")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    scope = getattr(args, "scope", [])

    if args.command == "plan":
        sched = ReconScheduler(
            mode=args.mode,
            scope_roots=scope or [args.target],
        )
        tasks = sched.plan(
            args.target,
            org=args.org,
            mode=args.mode,
            enqueue=not args.no_enqueue,
        )
        if args.raw_json:
            print(json.dumps(tasks, indent=2))
        else:
            _print_plan(tasks)

    elif args.command == "run":
        sched  = ReconScheduler(mode=args.mode, scope_roots=scope)
        result = sched.run(args.target, limit=args.limit, mode=args.mode)
        if args.raw_json:
            print(json.dumps(result, indent=2))
        else:
            _print_run(result)

    elif args.command == "status":
        sched   = ReconScheduler()
        summary = sched.status()
        if args.raw_json:
            print(json.dumps(summary, indent=2))
        else:
            _print_status(summary)

    elif args.command == "queue":
        sched = ReconScheduler()
        tasks = sched.queue(getattr(args, "target", None))
        if args.raw_json:
            print(json.dumps(tasks, indent=2))
        else:
            _print_queue(tasks)

    elif args.command == "flush":
        sched  = ReconScheduler()
        count  = sched.flush()
        result = {"flushed": count}
        if args.raw_json:
            print(json.dumps(result, indent=2))
        else:
            print(f"\n  Cleared {count} pending task(s) from the queue.\n")


if __name__ == "__main__":
    main()
