#!/usr/bin/env python3
"""
rek_asset_validation.py

FQDN validation, canonical form normalization, and duplicate detection.

is_valid_fqdn()   — RFC 1123 compliant validation
canonical_fqdn()  — normalize to lowercase, strip wildcards and trailing dot
detect_duplicate() — match a candidate against a set of known canonical forms
"""

import re
from typing import Optional, Set

# ---------------------------------------------------------------------------
# Regex for a single DNS label per RFC 1123
# Accepts single-char labels (e.g. "a") and 2-63 char labels.
# Labels must start and end with alnum; may contain hyphens internally.
# ---------------------------------------------------------------------------

_LABEL_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$"
    r"|^[a-z0-9]$",
)

_MAX_FQDN_LEN  = 253
_MAX_LABEL_LEN = 63

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def is_valid_fqdn(fqdn: str) -> bool:
    """
    Validate a Fully Qualified Domain Name per RFC 1123.

    Rules enforced
    --------------
    - Total length ≤ 253 characters (trailing dot excluded from count)
    - At least two labels (bare TLDs are not valid recon FQDNs)
    - Each label 1–63 characters
    - Labels contain only [a-z0-9-]; no leading or trailing hyphen
    - Not a raw IPv4 address (all-numeric labels)
    """
    if not fqdn or not isinstance(fqdn, str):
        return False

    name = fqdn.lower().rstrip(".")

    if len(name) > _MAX_FQDN_LEN:
        return False

    labels = name.split(".")

    if len(labels) < 2:
        return False  # bare single label — not a usable recon FQDN

    # Reject pure IPv4 addresses
    if all(part.isdigit() for part in labels):
        return False

    for label in labels:
        if not label or len(label) > _MAX_LABEL_LEN:
            return False
        if not _LABEL_RE.match(label):
            return False

    return True


# ---------------------------------------------------------------------------
# Canonical form
# ---------------------------------------------------------------------------


def canonical_fqdn(fqdn: str) -> str:
    """
    Produce the canonical form of an FQDN:
    lowercase → strip leading wildcard (*.) → strip trailing dot.
    """
    return fqdn.lower().strip().lstrip("*.").rstrip(".")


# ---------------------------------------------------------------------------
# Duplicate detection
# ---------------------------------------------------------------------------


def detect_duplicate(
    fqdn: str,
    known_canonical: Set[str],
) -> Optional[str]:
    """
    Return the matching canonical form from known_canonical if fqdn
    normalises to an already-known asset, else None.
    """
    c = canonical_fqdn(fqdn)
    return c if c in known_canonical else None
