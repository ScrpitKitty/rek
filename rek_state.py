#!/usr/bin/env python3
"""
rek_state.py

Persistent recon state graph for target intelligence accumulation.

Backed by a JSON file at state/recon_state.json. All writes are atomic
(temp file + os.replace) and protected by a threading.Lock so the module
is safe for concurrent use within a single process.

Entities
--------
  target     — root domain or IP being tracked
  subdomain  — discovered FQDN under a target domain
  service    — open port/protocol on a host
  endpoint   — URL path/method discovered on a service
  technology — fingerprinted tech stack for a host

Graph relationships
-------------------
  target     -> subdomain  (parent_domain)
  subdomain  -> service    (host == fqdn)
  service    -> endpoint   (host:port -> url)
  host       -> technology (host == fqdn or IP)

Deduplication keys
------------------
  target     : domain (lowercased)
  subdomain  : fqdn (lowercased)
  service    : host:port
  endpoint   : url:METHOD
  technology : host (lowercased)
"""

import json
import logging
import logging.handlers
import os
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_MODULE_DIR  = os.path.dirname(os.path.abspath(__file__))
_STATE_DIR   = os.path.join(_MODULE_DIR, "state")
_STATE_PATH  = os.path.join(_STATE_DIR, "recon_state.json")
_LOG_PATH    = os.path.join(_MODULE_DIR, "logs", "recon_state_updates.log")

# ---------------------------------------------------------------------------
# Dedicated state-update logger (isolated — never reaches root or stdout)
# ---------------------------------------------------------------------------

_slog = logging.getLogger("rek_state")
_slog.setLevel(logging.INFO)
_slog.propagate = False

os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)
_sfh = logging.handlers.RotatingFileHandler(
    _LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_sfh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_slog.addHandler(_sfh)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()

_ENTITY_KEYS = ("targets", "subdomains", "services", "endpoints", "technologies", "infrastructure")


# ---------------------------------------------------------------------------
# ReconStateGraph
# ---------------------------------------------------------------------------

class ReconStateGraph:
    """
    Thread-safe persistent recon state graph.

    All five entity dictionaries are keyed by a deterministic string so that
    deduplication is an O(1) dict lookup. Timestamps are updated on every
    re-discovery so the graph reflects recency without losing history.

    Public API
    ----------
    upsert_target(domain, root_ip)
    upsert_subdomain(fqdn, parent_domain, source_tool)
    upsert_service(host, port, protocol, service_name)
    upsert_endpoint(url, method, parameters)
    upsert_technology(host, tech_stack)

    get_known_subdomains(target)   -> List[str]
    get_new_subdomains(target, candidates) -> List[str]
    get_open_ports(host)           -> List[int]
    get_endpoints(host)            -> List[str]
    get_technology_stack(host)     -> List[str]
    get_target_state(target)       -> dict
    list_targets()                 -> List[dict]
    get_summary()                  -> dict
    """

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
                for key in _ENTITY_KEYS:
                    data.setdefault(key, {})
                return data
            except (json.JSONDecodeError, OSError) as e:
                _slog.warning("State file unreadable (%s) — starting fresh.", e)
        return {k: {} for k in _ENTITY_KEYS}

    def _flush(self) -> None:
        """Write state to disk atomically via temp file + os.replace."""
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._state, f, indent=2)
        os.replace(tmp, self._path)

    # ------------------------------------------------------------------
    # Target
    # ------------------------------------------------------------------

    def upsert_target(self, domain: str, root_ip: Optional[str] = None) -> bool:
        """Register or refresh a target. Returns True if newly added."""
        key = domain.lower().strip()
        with self._lock:
            if key not in self._state["targets"]:
                self._state["targets"][key] = {
                    "domain":       key,
                    "root_ip":      root_ip,
                    "first_seen":   _ts(),
                    "last_scanned": _ts(),
                }
                _slog.info("NEW_TARGET domain=%s", key)
                self._flush()
                return True
            else:
                rec = self._state["targets"][key]
                rec["last_scanned"] = _ts()
                if root_ip and not rec.get("root_ip"):
                    rec["root_ip"] = root_ip
                self._flush()
                return False

    # ------------------------------------------------------------------
    # Subdomains
    # ------------------------------------------------------------------

    def upsert_subdomain(
        self,
        fqdn: str,
        parent_domain: str,
        source_tool: str = "unknown",
    ) -> bool:
        """Add or refresh a subdomain. Returns True if newly added."""
        key = fqdn.lower().strip()
        with self._lock:
            if key not in self._state["subdomains"]:
                self._state["subdomains"][key] = {
                    "fqdn":          key,
                    "parent_domain": parent_domain.lower().strip(),
                    "source_tool":   source_tool,
                    "discovered_at": _ts(),
                    "last_seen":     _ts(),
                }
                _slog.info("NEW_SUBDOMAIN fqdn=%s source=%s", key, source_tool)
                self._flush()
                return True
            else:
                self._state["subdomains"][key]["last_seen"] = _ts()
                self._flush()
                return False

    def get_known_subdomains(self, target: str) -> List[str]:
        """Return all known FQDNs whose parent_domain matches target."""
        target = target.lower().strip()
        with self._lock:
            return [
                v["fqdn"]
                for v in self._state["subdomains"].values()
                if v["parent_domain"] == target
            ]

    def get_new_subdomains(self, target: str, candidates: List[str]) -> List[str]:
        """Return candidates not yet present in the state graph."""
        known = set(self.get_known_subdomains(target))
        return [s for s in candidates if s.lower().strip() not in known]

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    def upsert_service(
        self,
        host: str,
        port: int,
        protocol: str = "tcp",
        service_name: str = "",
    ) -> bool:
        """Add or refresh a service. Returns True if newly added."""
        key = f"{host.lower().strip()}:{port}"
        with self._lock:
            if key not in self._state["services"]:
                self._state["services"][key] = {
                    "host":         host.lower().strip(),
                    "port":         int(port),
                    "protocol":     protocol,
                    "service_name": service_name,
                    "discovered_at": _ts(),
                    "last_seen":    _ts(),
                }
                _slog.info("NEW_SERVICE host=%s port=%s proto=%s", host, port, protocol)
                self._flush()
                return True
            else:
                self._state["services"][key]["last_seen"] = _ts()
                self._flush()
                return False

    def get_open_ports(self, host: str) -> List[int]:
        """Return all known open ports for a host."""
        host = host.lower().strip()
        with self._lock:
            return [
                v["port"]
                for v in self._state["services"].values()
                if v["host"] == host
            ]

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------

    def upsert_endpoint(
        self,
        url: str,
        method: str = "GET",
        parameters: Optional[List[str]] = None,
    ) -> bool:
        """Add or refresh an endpoint. Returns True if newly added."""
        key = f"{url}:{method.upper()}"
        with self._lock:
            if key not in self._state["endpoints"]:
                self._state["endpoints"][key] = {
                    "url":          url,
                    "method":       method.upper(),
                    "parameters":   parameters or [],
                    "discovered_at": _ts(),
                    "last_seen":    _ts(),
                }
                _slog.info("NEW_ENDPOINT method=%s url=%s", method.upper(), url)
                self._flush()
                return True
            else:
                self._state["endpoints"][key]["last_seen"] = _ts()
                self._flush()
                return False

    def get_endpoints(self, host: str) -> List[str]:
        """Return all known endpoint URLs that contain host."""
        host = host.lower().strip()
        with self._lock:
            return [
                v["url"]
                for v in self._state["endpoints"].values()
                if host in v["url"].lower()
            ]

    # ------------------------------------------------------------------
    # Technologies
    # ------------------------------------------------------------------

    def upsert_technology(self, host: str, tech_stack: List[str]) -> bool:
        """Merge a tech stack for a host. Returns True if anything new added."""
        key = host.lower().strip()
        with self._lock:
            if key not in self._state["technologies"]:
                self._state["technologies"][key] = {
                    "host":         key,
                    "tech_stack":   list(set(tech_stack)),
                    "discovered_at": _ts(),
                    "last_seen":    _ts(),
                }
                _slog.info("NEW_TECHNOLOGY host=%s stack=%s", key, tech_stack)
                self._flush()
                return True
            else:
                existing  = set(self._state["technologies"][key]["tech_stack"])
                new_techs = set(tech_stack) - existing
                if new_techs:
                    self._state["technologies"][key]["tech_stack"] = list(existing | new_techs)
                    _slog.info("UPDATED_TECHNOLOGY host=%s added=%s", key, list(new_techs))
                self._state["technologies"][key]["last_seen"] = _ts()
                self._flush()
                return bool(new_techs)

    def get_technology_stack(self, host: str) -> List[str]:
        with self._lock:
            entry = self._state["technologies"].get(host.lower().strip())
            return entry["tech_stack"] if entry else []

    # ------------------------------------------------------------------
    # Infrastructure (ASN / CIDR blocks)
    # ------------------------------------------------------------------

    def upsert_infrastructure(
        self,
        target: str,
        cidr: str,
        asn: str = "",
        owner: str = "",
    ) -> bool:
        """Record a CIDR block associated with a target. Returns True if newly added."""
        key = f"{target.lower().strip()}:{cidr}"
        with self._lock:
            if key not in self._state["infrastructure"]:
                self._state["infrastructure"][key] = {
                    "target":        target.lower().strip(),
                    "cidr":          cidr,
                    "asn":           asn,
                    "owner":         owner,
                    "discovered_at": _ts(),
                    "last_seen":     _ts(),
                }
                _slog.info("NEW_INFRASTRUCTURE target=%s cidr=%s asn=%s", target, cidr, asn)
                self._flush()
                return True
            else:
                self._state["infrastructure"][key]["last_seen"] = _ts()
                self._flush()
                return False

    def get_infrastructure(self, target: str) -> List[dict]:
        """Return all CIDR records associated with a target."""
        target = target.lower().strip()
        with self._lock:
            return [
                v for v in self._state["infrastructure"].values()
                if v["target"] == target
            ]

    # ------------------------------------------------------------------
    # Aggregate queries
    # ------------------------------------------------------------------

    def get_target_state(self, target: str) -> dict:
        """
        Full aggregated intelligence snapshot for a target.

        Collects all subdomains, services, endpoints, and technology entries
        whose host set includes the target root domain and all its known FQDNs.
        """
        target = target.lower().strip()
        with self._lock:
            target_rec = self._state["targets"].get(target, {})

            subdomains = [
                v for v in self._state["subdomains"].values()
                if v["parent_domain"] == target
            ]
            all_hosts = {target} | {s["fqdn"] for s in subdomains}

            services = [
                v for v in self._state["services"].values()
                if v["host"] in all_hosts
            ]
            endpoints = [
                v for v in self._state["endpoints"].values()
                if any(h in v["url"].lower() for h in all_hosts)
            ]
            technologies = {
                h: self._state["technologies"][h]["tech_stack"]
                for h in all_hosts
                if h in self._state["technologies"]
            }

            return {
                "target":       target_rec,
                "subdomains":   subdomains,
                "services":     services,
                "endpoints":    endpoints,
                "technologies": technologies,
                "stats": {
                    "subdomains_count":  len(subdomains),
                    "services_count":    len(services),
                    "endpoints_count":   len(endpoints),
                    "hosts_with_tech":   len(technologies),
                },
            }

    def list_targets(self) -> List[dict]:
        """Return all tracked target records."""
        with self._lock:
            return list(self._state["targets"].values())

    def get_summary(self) -> dict:
        """Return entity counts and state file path."""
        with self._lock:
            return {
                "targets":        len(self._state["targets"]),
                "subdomains":     len(self._state["subdomains"]),
                "services":       len(self._state["services"]),
                "endpoints":      len(self._state["endpoints"]),
                "technologies":   len(self._state["technologies"]),
                "infrastructure": len(self._state["infrastructure"]),
                "state_file":     self._path,
            }


# ---------------------------------------------------------------------------
# Module-level singleton — imported directly by rek_mcp_server
# ---------------------------------------------------------------------------

state_graph = ReconStateGraph()
