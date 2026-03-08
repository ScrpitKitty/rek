#!/usr/bin/env python3
"""
rek_source_trust.py

Source trust weight table and confidence scoring for false-positive
suppression.

Trust weights
-------------
  certificate_transparency (crt.sh)    : 3
  certificate_san (tls_san)            : 2
  passive_dns (hackertarget,threatminer): 2 each
  active confirmation (port_scan)      : 4
  active confirmation (http_response)  : 3
  unknown / weak                       : 1

Confidence score = sum of trust weights for each unique source in
an asset's source_list.
"""

from typing import List

# ---------------------------------------------------------------------------
# Trust weight table
# ---------------------------------------------------------------------------

SOURCE_WEIGHTS: dict = {
    # Passive expansion (from rek_expand.py source names)
    "crt.sh":          3,   # certificate transparency
    "tls_san":         2,   # TLS certificate SAN extraction
    "hackertarget":    2,   # passive DNS
    "threatminer":     2,   # passive DNS
    "asn_reverse_dns": 1,   # ASN reverse-DNS (weak)
    # Active confirmation
    "port_scan":       4,   # naabu confirmed open port
    "http_response":   3,   # direct HTTP response from host
    # External passive enumeration tools
    "subfinder":       2,
    "amass":           2,
    # Fallback
    "unknown":         1,
}

# Sources classified as weak (single occurrence → defer)
WEAK_SOURCES = frozenset({"asn_reverse_dns", "unknown"})

# Sources classified as passive-DNS-only (historical, no live confirmation)
PASSIVE_DNS_SOURCES = frozenset({"hackertarget", "threatminer", "asn_reverse_dns"})

# Sources that count as strong independent confirmation
STRONG_SOURCES = frozenset({"crt.sh", "tls_san", "port_scan", "http_response"})

# ---------------------------------------------------------------------------
# Confidence calculator
# ---------------------------------------------------------------------------


def get_confidence(source_list: List[str]) -> int:
    """
    Sum trust weights for each unique source in source_list.

    Each source is counted at most once regardless of how many times it
    appears in the list.
    """
    seen  = set()
    total = 0
    for src in source_list:
        src = src.lower().strip()
        if src not in seen:
            seen.add(src)
            total += SOURCE_WEIGHTS.get(src, SOURCE_WEIGHTS["unknown"])
    return total


def count_strong_sources(source_list: List[str]) -> int:
    """Return the number of distinct strong sources present."""
    return len({s.lower().strip() for s in source_list} & STRONG_SOURCES)


def is_passive_dns_only(source_list: List[str]) -> bool:
    """Return True if every source in source_list is a passive-DNS source."""
    sources = {s.lower().strip() for s in source_list}
    return bool(sources) and sources.issubset(PASSIVE_DNS_SOURCES)


def is_single_weak_source(source_list: List[str]) -> bool:
    """Return True if there is exactly one source and it is a weak source."""
    sources = {s.lower().strip() for s in source_list}
    return len(sources) == 1 and sources.issubset(WEAK_SOURCES)
