"""Scope enforcement - the security core of the platform.

Every target is evaluated here BEFORE a task is planned on the master AND
again before any command executes on the worker (defense in depth).
Semantics:

* **Default deny** - anything not explicitly in scope is out of scope.
* **Deny wins** - explicit out-of-scope entries override allow entries.
* Wildcard domains (``*.api.example.com``), plain domains (apex + subdomains),
  IPv4/IPv6 literals and CIDR ranges are supported.
* Cloud/metadata endpoints, loopback and link-local addresses are hard-blocked
  even if someone puts them in scope (they are never valid bug bounty targets
  and are a classic SSRF pivot).
* Targets are strictly sanitized; tool arguments are always passed as argv
  lists, never through a shell.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# Characters allowed in a target string. Anything else is rejected outright,
# which structurally prevents argument/shell injection via targets.
_SAFE_TARGET_RE = re.compile(r"^[a-z0-9.:\-*\[\]]{1,253}$")

# Hard-blocked ranges regardless of configuration.
HARD_BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("169.254.0.0/16"),   # link-local incl. cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]
HARD_BLOCKED_HOSTS = {
    "metadata.google.internal",
    "169.254.169.254",
    "localhost",
    "ip6-localhost",
}

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


class InvalidTarget(ValueError):
    """Raised when a target fails structural sanitization."""


class OutOfScopeError(PermissionError):
    """Raised when a target is not covered by an allow entry (or hits a deny)."""


def _validate_domain(domain: str) -> None:
    labels = domain.split(".")
    if len(domain) > 253 or any(not lbl or len(lbl) > 63 for lbl in labels):
        raise InvalidTarget(f"invalid domain pattern: {domain}")
    if any(not _LABEL_RE.match(lbl) for lbl in labels):
        raise InvalidTarget(f"invalid characters in domain pattern: {domain}")


@dataclass(frozen=True)
class ScopeEntry:
    pattern: str      # normalized pattern (lowercase)
    kind: str         # 'domain' | 'cidr' | 'wildcard'
    is_allowed: bool

    @staticmethod
    def parse(pattern: str, is_allowed: bool) -> "ScopeEntry":
        raw = pattern.strip().lower().rstrip(".")
        if raw.startswith("*."):
            _validate_domain(raw[2:])
            return ScopeEntry(raw, "wildcard", is_allowed)
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            pass
        else:
            return ScopeEntry(str(net), "cidr", is_allowed)
        try:
            ipaddress.ip_address(raw)
        except ValueError:
            pass
        else:
            addr = ipaddress.ip_address(raw)  # bare IP -> /32 or /128
            return ScopeEntry(
                str(ipaddress.ip_network(f"{raw}/{addr.max_prefixlen}", strict=False)),
                "cidr",
                is_allowed,
            )
        _validate_domain(raw)
        return ScopeEntry(raw, "domain", is_allowed)


def normalize_target(raw: str) -> str:
    """Sanitize + normalize a user-supplied target.

    Strips scheme/port/path, lowercases, applies IDNA (punycode) encoding so
    homograph Unicode domains cannot smuggle past matching.
    """
    if not isinstance(raw, str):
        raise InvalidTarget("target must be a string")
    value = raw.strip().lower()
    if "://" in value:                      # strip scheme
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]          # strip path
    value = value.split("@")[-1]            # strip userinfo
    if ":" in value and not _looks_like_ipv6(value):
        value = value.rsplit(":", 1)[0]     # strip port
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]                 # [::1] bracket form
    # IDNA-encode BEFORE charset validation so Unicode homographs are folded
    # into their punycode form instead of being rejected outright.
    if not value.isascii() and "*" not in value and not _looks_like_ipv6(value):
        try:
            value = value.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise InvalidTarget(f"target failed IDNA encoding: {raw!r}") from exc
    if not _SAFE_TARGET_RE.match(value):
        raise InvalidTarget(f"target contains forbidden characters: {raw!r}")
    return value.rstrip(".")


def _looks_like_ipv6(value: str) -> bool:
    return value.count(":") >= 2


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("*"))
        return True
    except ValueError:
        return False


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    matched_pattern: str | None = field(default=None)


def evaluate(target_raw: str, entries: list[ScopeEntry]) -> ScopeDecision:
    """Evaluate one target against the policy. Deny wins; default deny."""
    target = normalize_target(target_raw)

    # Hard blocks first (loopback / metadata), independent of configuration.
    if target in HARD_BLOCKED_HOSTS:
        return ScopeDecision(False, "hard-blocked endpoint")
    if _looks_like_ip(target):
        addr = ipaddress.ip_address(target)
        if any(addr in net for net in HARD_BLOCKED_NETS):
            return ScopeDecision(False, "hard-blocked network (loopback/link-local)")

    denies = [e for e in entries if not e.is_allowed]
    allows = [e for e in entries if e.is_allowed]

    for entry in denies:
        if _matches(entry, target):
            return ScopeDecision(
                False, f"explicitly out of scope (deny: {entry.pattern})", entry.pattern
            )
    for entry in allows:
        if _matches(entry, target):
            return ScopeDecision(True, f"in scope ({entry.pattern})", entry.pattern)

    return ScopeDecision(False, "not covered by any in-scope entry (default deny)")


def _matches(entry: ScopeEntry, target: str) -> bool:
    if entry.kind == "cidr":
        try:
            return ipaddress.ip_address(target) in ipaddress.ip_network(entry.pattern)
        except ValueError:
            return False
    if entry.kind == "wildcard":
        suffix = entry.pattern[1:]  # '*.api.x.com' -> '.api.x.com'
        return target.endswith(suffix)
    # plain domain: apex itself or any subdomain
    return target == entry.pattern or target.endswith("." + entry.pattern)


def assert_in_scope(target_raw: str, entries: list[ScopeEntry]) -> ScopeDecision:
    """Evaluate and raise OutOfScopeError unless explicitly authorized."""
    decision = evaluate(target_raw, entries)
    if not decision.allowed:
        raise OutOfScopeError(f"{target_raw}: {decision.reason}")
    return decision


def load_entries(rows: list[tuple[str, bool]]) -> list[ScopeEntry]:
    """Build ScopeEntry objects from (pattern, is_allowed) DB rows.

    Malformed patterns are skipped but logged - a broken pattern must never
    widen the scope.
    """
    import logging

    entries: list[ScopeEntry] = []
    for pattern, allowed in rows:
        try:
            entries.append(ScopeEntry.parse(pattern, bool(allowed)))
        except InvalidTarget:
            logging.getLogger(__name__).warning(
                "skipping malformed scope pattern", extra={"pattern": str(pattern)}
            )
    return entries


