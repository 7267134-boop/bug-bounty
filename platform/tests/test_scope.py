"""Security-critical tests for the scope enforcement module."""

import pytest

from common.scope import (
    HARD_BLOCKED_HOSTS,
    InvalidTarget,
    OutOfScopeError,
    ScopeEntry,
    assert_in_scope,
    evaluate,
    load_entries,
    normalize_target,
)


def policy(*entries: tuple[str, bool]) -> list[ScopeEntry]:
    return [ScopeEntry.parse(p, allowed) for p, allowed in entries]


class TestNormalization:
    def test_strips_scheme_path_port(self):
        assert normalize_target("HTTPS://Example.com:8443/path") == "example.com"

    def test_lowercases_and_trims_dot(self):
        assert normalize_target("  EXAMPLE.COM. ") == "example.com"

    @pytest.mark.parametrize("bad", [
        "example.com; rm -rf /", "a b.com", "example$(id).com",
        "example.com' OR 1=1 --", "", None, 12345, "exa mple.com",
    ])
    def test_injection_attempts_rejected(self, bad):
        with pytest.raises(InvalidTarget):
            normalize_target(bad)  # type: ignore[arg-type]

    def test_hard_blocked_hosts_denied_by_policy(self):
        # Hard-blocked endpoints are not "malformed" - they get an explicit
        # DENY decision from evaluate()/assert_in_scope().
        for host in ("localhost", "169.254.169.254", "metadata.google.internal"):
            with pytest.raises(OutOfScopeError):
                assert_in_scope(host, policy(("example.com", True)))
            assert not evaluate(host, policy((host, True))).allowed

    def test_punycode_encoding(self):
        # Unicode homograph: bücher.example.com -> xn--bcher.example.com
        out = normalize_target("bücher.example.com")
        assert out.startswith("xn--")


class TestDomainMatching:
    ENTRIES = policy(
        ("example.com", True),
        ("*.api.example.com", True),
        ("admin.example.com", False),      # explicit deny
        ("old.example.com", False),
    )

    @pytest.mark.parametrize("target", [
        "example.com", "www.example.com", "deep.sub.example.com",
        "x.api.example.com", "y.z.api.example.com",
        # also covered by the broad example.com allow (apex + all subs):
        "api.example.com",
    ])
    def test_allowed(self, target):
        assert evaluate(target, self.ENTRIES).allowed

    @pytest.mark.parametrize("target", [
        "admin.example.com",               # deny entry wins over *.example allow
        "notexample.com",                  # suffix look-alike must NOT match
        "example.org",                     # different TLD
        "attacker-example.com",
        "unknown.net",
    ])
    def test_denied_or_default_deny(self, target):
        assert not evaluate(target, self.ENTRIES).allowed

    def test_wildcard_apex_not_included(self):
        # With ONLY the wildcard in scope, its apex is NOT covered.
        entries = policy(("*.api.example.com", True))
        assert not evaluate("api.example.com", entries).allowed
        assert evaluate("v.api.example.com", entries).allowed


class TestIpCidr:
    ENTRIES = policy(("192.0.2.0/24", True))

    def test_ip_inside_cidr(self):
        assert evaluate("192.0.2.55", self.ENTRIES).allowed

    def test_ip_outside_cidr_default_deny(self):
        assert not evaluate("198.51.100.1", self.ENTRIES).allowed

    def test_domain_never_matches_cidr_entry(self):
        assert not evaluate("www.example.com", self.ENTRIES).allowed


class TestHardBlocks:
    def test_loopback_denied_even_if_in_scope(self):
        entries = policy(("127.0.0.1", True))
        assert not evaluate("127.0.0.1", entries).allowed

    def test_metadata_range_denied_even_if_in_scope(self):
        entries = policy(("169.254.0.0/16", True))
        assert not evaluate("169.254.169.254", entries).allowed


class TestDenyWins:
    def test_deny_beats_allow_for_subdomain(self):
        entries = policy(("*", True), ("secret.example.com", False)) \
            if False else policy(("example.com", True), ("secret.example.com", False))
        d = evaluate("secret.example.com", entries)
        assert not d.allowed and "deny" in d.reason


class TestAssertHelpers:
    def test_assert_raises_out_of_scope(self):
        with pytest.raises(OutOfScopeError):
            assert_in_scope("nope.example.org", policy(("example.com", True)))

    def test_load_entries_skips_malformed_patterns(self, caplog):
        rows = [("good.example.com", True), ("not a domain!!", True)]
        entries = load_entries(rows)
        assert len(entries) == 1 and entries[0].pattern == "good.example.com"


def test_hard_block_set_contents():
    assert "169.254.169.254" in HARD_BLOCKED_HOSTS
