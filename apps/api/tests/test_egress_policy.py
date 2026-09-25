"""egress_policy.py, the one address classifier, destination rule and code
table every outbound client and the egress proxy share (2026-09-24;
docs/00 decisions 68 and 77, docs/20 section 2).

Pure: no database and no network. A fake getaddrinfo stands in for the
resolver, as the rebinding suite does, because resolve_and_pin looks the
function up as a module attribute of `socket`.
"""
from __future__ import annotations

import ast
import inspect
import ipaddress
import socket
from uuid import uuid4

import pytest

from noctornal_api import collection, egress_policy, pinned_http
from noctornal_api.egress_policy import (
    CLIENT_CODES,
    CODE_EXCEPTION,
    CODES,
    DECISION_REF,
    PROXY_STATUS,
    PUBLIC_POLICY,
    SOCKS5_REPLY,
    WIRE_CODES,
    AddressClass,
    EgressRoute,
    Refusal,
    RoutePolicy,
    Rule,
    Unresolvable,
    admit,
    check_destination,
    classify,
    format_rule,
    internal_networks,
    locality,
    normalise_host,
    parse_rule,
    parse_wire_username,
    resolve_and_pin,
    validate_rule,
    wire_username,
)

_ip = ipaddress.ip_address
RUN = f"run:{uuid4()}"
TOKEN = "t" * 43


def _refused(code, fn, *args, **kwargs):
    with pytest.raises(Refusal) as caught:
        fn(*args, **kwargs)
    assert caught.value.code == code, (caught.value.code, str(caught.value))
    return caught.value


class _Resolver:
    """Answers every name with `answers`, counting the lookups."""

    def __init__(self, *answers: str):
        self.answers = answers
        self.calls = 0

    def __call__(self, host, port, *args, **kwargs):
        self.calls += 1
        out = []
        for a in self.answers:
            family = socket.AF_INET6 if ":" in a else socket.AF_INET
            sockaddr = (a, int(port), 0, 0) if family == socket.AF_INET6 else (a, int(port))
            out.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
        return out


# ---------------------------------------------------------------------------
# The classifier, moved verbatim
# ---------------------------------------------------------------------------

_COLLECTOR_REFUSED = [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
    "::1", "fc00::1", "fe80::1", "0.0.0.0", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
    "::", "100.64.1.1", "192.0.0.192", "198.18.0.1", "2002:7f00:1::", "224.0.0.1",
]
_COLLECTOR_PUBLIC = ["8.8.8.8", "1.1.1.1", "2606:4700::1111"]


@pytest.mark.parametrize("address", _COLLECTOR_REFUSED)
def test_the_collector_vectors_are_refused_here_too(address):
    """test_collection_hardening's table through every new entry point."""
    assert egress_policy.is_blocked(_ip(address))
    assert classify(_ip(address)) is not AddressClass.PUBLIC
    with pytest.raises(Refusal):
        admit(_ip(address), policy=PUBLIC_POLICY, rule=None)


@pytest.mark.parametrize("address", _COLLECTOR_PUBLIC)
def test_the_collector_public_vectors_pass(address):
    assert not egress_policy.is_blocked(_ip(address))
    assert admit(_ip(address), policy=PUBLIC_POLICY, rule=None) is AddressClass.PUBLIC


def test_collection_names_are_the_policy_objects():
    assert collection._is_blocked is egress_policy.is_blocked
    assert collection._BLOCKED_NETWORKS is egress_policy.BLOCKED_NETWORKS
    assert collection._METADATA_HOSTS is egress_policy.METADATA_HOSTS


_METADATA = ["169.254.169.254", "169.254.170.2", "fd00:ec2::254", "fd20:ce::254",
             "100.100.100.200", "192.0.0.192", "168.63.129.16"]


@pytest.mark.parametrize("address", _METADATA)
def test_metadata_addresses_are_refused_under_every_policy(address):
    """Including a public one (Azure's 168.63.129.16), the IPv4-mapped form,
    an integration rule whose network contains it, and a literal under
    admission "proxy", which classifies nothing else."""
    a = _ip(address)
    assert classify(a) is AddressClass.METADATA
    _refused("metadata_address", admit, a, policy=PUBLIC_POLICY, rule=None)
    if a.version == 4:
        _refused("metadata_address", admit, _ip(f"::ffff:{address}"),
                 policy=PUBLIC_POLICY, rule=None)
    network = ipaddress.ip_network(f"{address}/{a.max_prefixlen}")
    rule = Rule(frozenset({80}), network=network)
    integration = RoutePolicy("integration", (rule,), any_public=False,
                              allow_loopback=True)
    _refused("metadata_address", admit, a, policy=integration, rule=rule)
    proxied = RoutePolicy("integration", (rule,), any_public=False, admission="proxy")
    _refused("metadata_address", check_destination, proxied, address, 80)
    _refused("metadata_address", check_destination, PUBLIC_POLICY, address, 80)


def test_a_private_rule_admits_only_answers_inside_its_network():
    rule = parse_rule("jira.corp.example@10.20.0.0/24:443")
    policy = RoutePolicy("integration", (rule,), any_public=False)
    assert admit(_ip("10.20.0.5"), policy=policy, rule=rule) is AddressClass.PRIVATE
    _refused("outside_declared_network", admit, _ip("10.21.0.5"), policy=policy, rule=rule)
    _refused("outside_declared_network", admit, _ip("8.8.8.8"), policy=policy, rule=rule)


def test_a_mixed_answer_refuses_the_whole_host(monkeypatch):
    rule = parse_rule("jira.corp.example@10.20.0.0/24:443")
    policy = RoutePolicy("integration", (rule,), any_public=False)
    resolver = _Resolver("10.20.0.5", "8.8.8.8")
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    _refused("outside_declared_network", resolve_and_pin, "jira.corp.example", 443,
             policy=policy, rule=rule, route_label="jira")
    assert resolver.calls == 1


def test_a_public_network_rule_admits_public_addresses_inside_it():
    rule = parse_rule("149.154.160.0/20:443")
    policy = RoutePolicy("persona", (rule,), any_public=False)
    assert admit(_ip("149.154.167.51"), policy=policy, rule=rule) is AddressClass.PUBLIC
    _refused("outside_declared_network", admit, _ip("149.154.176.1"), policy=policy, rule=rule)


def test_a_persona_route_never_admits_private_space_whatever_its_rules():
    rule = Rule(frozenset({443}), network="10.20.0.0/24")
    policy = RoutePolicy("persona", (rule,))
    _refused("blocked_address", admit, _ip("10.20.0.5"), policy=policy, rule=rule)
    assert validate_rule(rule, kind="persona", production=False)


def test_a_mapped_or_6to4_address_is_unwrapped_before_membership():
    rule = parse_rule("jira.corp.example@10.20.0.0/24:443")
    policy = RoutePolicy("integration", (rule,), any_public=False)
    assert admit(_ip("::ffff:10.20.0.5"), policy=policy, rule=rule) is AddressClass.PRIVATE
    six = Rule(frozenset({443}), network="2002:a14:5::/48")
    assert validate_rule(six, kind="integration", production=False)
    with pytest.raises(Refusal):
        admit(_ip("2002:0a14:0005::"), policy=PUBLIC_POLICY, rule=None)


def test_loopback_needs_the_development_flag():
    rule = Rule.for_host("localhost", {1025})
    without = RoutePolicy("integration", (rule,), any_public=False)
    with_flag = RoutePolicy("integration", (rule,), any_public=False, allow_loopback=True)
    _refused("loopback_refused", admit, _ip("127.0.0.1"), policy=without, rule=rule)
    assert admit(_ip("127.0.0.1"), policy=with_flag, rule=rule) is AddressClass.LOOPBACK
    assert admit(_ip("::1"), policy=with_flag, rule=rule) is AddressClass.LOOPBACK


def test_an_internal_network_answer_is_refused_on_every_route():
    internal = internal_networks({}, production=True)
    rule = parse_rule("x.corp.example@172.31.243.0/24:443")
    assert validate_rule(rule, kind="integration", production=True, internal=internal)
    forced = RoutePolicy("integration", (rule,), any_public=False, internal=internal)
    _refused("internal_address", admit, _ip("172.31.243.9"), policy=forced, rule=rule)
    persona = RoutePolicy("persona", internal=internal)
    _refused("internal_address", admit, _ip("172.31.244.2"), policy=persona, rule=None)


def test_internal_networks_reads_the_variable_and_the_production_default():
    assert [str(n) for n in internal_networks({}, production=True)] == [
        "172.31.243.0/24", "172.31.244.0/24"]
    assert internal_networks({}, production=False) == ()
    # Blank is unset: a compose `VAR: ""` must not switch the guard off.
    assert len(internal_networks({egress_policy.INTERNAL_CIDRS_ENV: "  "},
                                 production=True)) == 2
    assert [str(n) for n in internal_networks(
        {egress_policy.INTERNAL_CIDRS_ENV: "10.9.0.0/24, fd00:9::/64"},
        production=False)] == ["10.9.0.0/24", "fd00:9::/64"]
    for bad in ("10.9.0.0/33", "not-a-net", "10.9.0.1/24", "10.9.0.0/24,,"):
        with pytest.raises(ValueError, match="comma list of networks"):
            internal_networks({egress_policy.INTERNAL_CIDRS_ENV: bad}, production=True)


def test_validate_rule_refuses_wide_foreign_reserved_and_internal_networks():
    internal = internal_networks({}, production=True)
    for text in ("10.0.0.0/8:443", "192.0.0.0/24:443", "198.18.0.0/15:443",
                 "169.254.0.0/16:443", "[fe80::/10]:443", "[fd00::/48]:443",
                 "postgres:5432", "172.31.243.0/24:443",
                 "x.corp.example@172.31.243.0/24:443", ".corp.example:443",
                 "127.0.0.1:1025"):
        rule = parse_rule(text)
        assert validate_rule(rule, kind="integration", production=True,
                             internal=internal), text
    assert validate_rule(parse_rule("[fd00:1::/64]:443"), kind="integration",
                         production=True, internal=internal) == []
    assert validate_rule(parse_rule("jira.corp.example@10.20.0.0/24:443"),
                         kind="integration", production=True, internal=internal) == []
    assert validate_rule(parse_rule(".example.com:443"), kind="persona",
                         production=True) == []
    assert validate_rule(parse_rule(".com:443"), kind="persona", production=True)
    for sentence in validate_rule(parse_rule("10.0.0.0/8:443"), kind="persona",
                                  production=True):
        assert "—" not in sentence and "–" not in sentence
        assert "(s)" not in sentence


def test_localhost_is_a_development_integration_host_only():
    """CI and development send mail to a local Mailpit (ci.yml SMTP_HOST:
    localhost; the installers write 127.0.0.1), so both spellings are
    expressible outside production and refused in it."""
    for rule in (Rule.for_host("localhost", {1025}), Rule.for_host("127.0.0.1", {1025}),
                 Rule.for_host("::1", {1025})):
        assert validate_rule(rule, kind="integration", production=False) == [], rule
        assert validate_rule(rule, kind="integration", production=True), rule
        assert validate_rule(rule, kind="persona", production=False), rule
    assert egress_policy.rule_networks(Rule.for_host("localhost", {1025})) == \
        egress_policy.LOOPBACK_NETWORKS


def test_a_dual_stack_localhost_answer_is_admitted_whole(monkeypatch):
    """Windows answers ::1 and 127.0.0.1 for localhost; a rule implying one
    loopback network refused the whole host on the other."""
    rule = Rule.for_host("localhost", {1025})
    policy = RoutePolicy("integration", (rule,), any_public=False, allow_loopback=True)
    monkeypatch.setattr(socket, "getaddrinfo", _Resolver("::1", "127.0.0.1"))
    pinned = resolve_and_pin("localhost", 1025, policy=policy, rule=rule, route_label="smtp")
    assert [a[3][0] for a in pinned.addresses] == ["::1", "127.0.0.1"]
    assert pinned.locality == "loopback"


def test_rule_grammar_round_trips():
    for text in ("jira.corp.example:443", "jira.corp.example:80,443",
                 ".example.com:443", "149.154.160.0/20:443,80,5222",
                 "jira.corp.example@10.20.0.0/24:443", "[fd00:1::/64]:443",
                 "jira.corp.example@[fd00:1::/64]:8443", "10.0.5.20:8000",
                 "[fd00::5]:443", "xn--bcher-kva.de:443"):
        rule = parse_rule(text)
        assert parse_rule(format_rule(rule)) == rule, text
    # An address written as a host is a network rule of that one address.
    assert parse_rule("10.0.5.20:8000") == Rule(frozenset({8000}), network="10.0.5.20/32")
    assert format_rule(parse_rule("10.0.5.20:8000")) == "10.0.5.20/32:8000"
    for bad in ("host", ":443", "[::1]", "*.example.com:443", "x:0", "x:65536",
                "x:", "fd00::1:443", "a@b@10.0.0.0/24:443", "10.0.0.1@10.0.0.0/24:443",
                "10.0.0.5/24:443", ""):
        with pytest.raises(ValueError):
            parse_rule(bad)


def test_suffix_matches_only_on_a_label_boundary():
    policy = RoutePolicy("persona", (parse_rule(".example.com:443"),), any_public=False,
                         admission="proxy")
    assert check_destination(policy, "example.com", 443) is not None
    assert check_destination(policy, "sub.example.com", 443) is not None
    assert check_destination(policy, "EXAMPLE.com.", 443) is not None
    _refused("destination_not_allowed", check_destination, policy, "evil-example.com", 443)
    idn = RoutePolicy("persona", (Rule(frozenset({443}), suffix="bücher.de"),),
                      any_public=False, admission="proxy")
    assert check_destination(idn, "shop.xn--bcher-kva.de", 443) is not None
    assert check_destination(idn, "shop.bücher.de", 443) is not None


@pytest.mark.parametrize("host", [
    "fe80::1%eth0", "a" * 64 + ".example", ("a" * 60 + ".") * 5 + "com",
    "xn--.example", "exa mple.com", "2130706433", "127.1", "0x7f.1", "0177.0.0.1",
    # UTS-46 maps these into an address or a numeric name; normalise_host is
    # idempotent, so it judges the mapped result.
    "127。0。0。1", "１２７.0.0.1", "0x7f。1",
])
def test_normalise_host_refuses_what_it_cannot_name(host):
    _refused("bad_host", normalise_host, host)


def test_normalise_host_is_idempotent_and_spells_one_way():
    for raw, want in (("Example.COM.", "example.com"),
                      ("::FFFF:127.0.0.1", "::ffff:127.0.0.1"),
                      ("bücher.de", "xn--bcher-kva.de"), ("[fd00::1]", "fd00::1"),
                      ("FD00:0::1", "fd00::1"), ("_srv.corp.example", "_srv.corp.example")):
        first = normalise_host(raw)
        assert first == want, raw
        assert normalise_host(first) == first, raw


def test_a_mapped_metadata_name_is_still_the_metadata_host():
    _refused("metadata_host", egress_policy.split_url,
             "http://metadata。google。internal/computeMetadata/v1/")
    _refused("metadata_host", check_destination, PUBLIC_POLICY,
             "metadata。google。internal", 80)


def test_special_names_are_refused_only_where_the_policy_says():
    special = RoutePolicy("persona", refuse_special_names=True, admission="proxy")
    for host in ("localhost", "printer.local", "db.internal", "nas.home.arpa"):
        _refused("blocked_name", check_destination, special, host, 443)
        assert check_destination(PUBLIC_POLICY, host, 443) is None


def test_an_onion_name_needs_the_onion_flag():
    name = "a" * 56 + ".onion"
    _refused("onion_not_allowed", check_destination, PUBLIC_POLICY, name, 80)
    tor = RoutePolicy("persona", onion=True, admission="proxy")
    assert check_destination(tor, name, 80) is None


def test_check_destination_refuses_a_matched_name_on_the_wrong_port_and_any_public_honours_its_ports():
    policy = RoutePolicy("persona", (parse_rule("forum.example:443"),),
                         any_public_ports=frozenset({443}), admission="proxy")
    assert check_destination(policy, "forum.example", 443) is not None
    _refused("port_not_allowed", check_destination, policy, "forum.example", 80)
    assert check_destination(policy, "other.example", 443) is None
    _refused("port_not_allowed", check_destination, policy, "other.example", 8080)


@pytest.mark.parametrize("admission", ["local", "proxy"])
def test_an_ip_literal_matches_only_a_network_rule_on_a_listed_port(admission):
    """Once a literal matched any rule whose network contained it, on any
    port, host@network rules included."""
    net = RoutePolicy("integration", (parse_rule("10.20.0.0/24:443"),),
                      any_public=False, admission=admission)
    _refused("port_not_allowed", check_destination, net, "10.20.0.7", 22)
    assert check_destination(net, "10.20.0.7", 443) is not None
    named = RoutePolicy("integration", (parse_rule("jira.corp.example@10.20.0.0/24:443"),),
                        any_public=False, admission=admission)
    _refused("destination_not_allowed", check_destination, named, "10.20.0.7", 443)
    tg = RoutePolicy("persona", (parse_rule("149.154.160.0/20:443"),),
                     any_public=False, admission=admission)
    _refused("port_not_allowed", check_destination, tg, "149.154.167.51", 80)
    declared = Rule.for_url("https://203.0.113.5/hook")
    hook = RoutePolicy("integration", (declared,), any_public=False, admission=admission)
    if admission == "local":
        # 203.0.113.0/24 is documentation space; the seam stands it in for
        # a public address the way the collector's suites do.
        assert check_destination(hook, "203.0.113.5", 443,
                                 _blocked_override=lambda a: False) == declared
    else:
        assert check_destination(hook, "203.0.113.5", 443) == declared
    _refused("port_not_allowed", check_destination, hook, "203.0.113.5", 80,
             _blocked_override=lambda a: False)
    _refused("destination_not_allowed", check_destination, hook, "203.0.113.6", 443,
             _blocked_override=lambda a: False)


def test_narrowing_never_adds_a_destination():
    admin = (parse_rule("jira.corp.example@10.20.0.0/24:443"),)
    other = RoutePolicy("integration", admin, narrow=(parse_rule("other.example:443"),),
                        any_public=False, admission="proxy")
    _refused("destination_not_allowed", check_destination, other, "jira.corp.example", 443)
    _refused("destination_not_allowed", check_destination, other, "other.example", 443)
    own = RoutePolicy("integration", admin, narrow=(parse_rule("jira.corp.example:443"),),
                      any_public=False, admission="proxy")
    assert check_destination(own, "jira.corp.example", 443) == admin[0]


def test_an_ip_literal_uses_the_seam():
    assert check_destination(PUBLIC_POLICY, "127.0.0.1", 80,
                             _blocked_override=lambda a: False) is None
    refusal = _refused("blocked_address", check_destination, PUBLIC_POLICY, "127.0.0.1", 80)
    assert str(refusal) == (
        "127.0.0.1 resolves into private address space, which a watch target "
        "must not: fetching it would reach this deployment's own internal network")
    proxied = RoutePolicy("persona", admission="proxy")
    assert check_destination(proxied, "127.0.0.1", 80) is None


def test_resolve_and_pin_makes_one_lookup_and_refuses_a_mixed_answer(monkeypatch):
    resolver = _Resolver("8.8.8.8", "10.0.0.1")
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    _refused("blocked_address", resolve_and_pin, "mixed.test", 80,
             policy=PUBLIC_POLICY, rule=None)
    assert resolver.calls == 1
    monkeypatch.setattr(socket, "getaddrinfo", _Resolver("8.8.8.8", "8.8.8.8", "1.1.1.1"))
    pinned = resolve_and_pin("public.test", 80, policy=PUBLIC_POLICY, rule=None)
    assert [a[3][0] for a in pinned.addresses] == ["8.8.8.8", "1.1.1.1"]
    assert pinned.locality == "global"


def test_resolve_and_pin_honours_the_seam(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _Resolver("127.0.0.1"))
    pinned = resolve_and_pin("stand.in", 80, policy=PUBLIC_POLICY, rule=None,
                             _blocked_override=lambda a: str(a) != "127.0.0.1")
    assert pinned.addresses[0][3][0] == "127.0.0.1"
    _refused("blocked_address", resolve_and_pin, "stand.in", 80,
             policy=PUBLIC_POLICY, rule=None)


def test_the_blocked_message_is_the_collectors_text(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _Resolver("10.0.0.1"))
    refusal = _refused("blocked_address", resolve_and_pin, "feed.test", 80,
                       policy=PUBLIC_POLICY, rule=None)
    assert str(refusal) == (
        "feed.test resolves into private address space, which a watch "
        "target must not: fetching it would reach this "
        "deployment's own internal network")
    labelled = _refused("blocked_address", resolve_and_pin, "feed.test", 80,
                        policy=RoutePolicy("integration", any_public=True), rule=None,
                        route_label="jira")
    assert "the jira route" in str(labelled)


def test_nxdomain_is_permanent_and_a_timeout_is_not(monkeypatch):
    def failing(errno):
        def resolver(*_a, **_k):
            raise socket.gaierror(errno, "resolver says no")
        return resolver

    permanent = [socket.EAI_NONAME] + (
        [socket.EAI_NODATA] if hasattr(socket, "EAI_NODATA") else [])
    for errno in permanent:
        monkeypatch.setattr(socket, "getaddrinfo", failing(errno))
        with pytest.raises(Unresolvable) as caught:
            resolve_and_pin("gone.test", 443, policy=PUBLIC_POLICY, rule=None)
        assert caught.value.permanent and caught.value.code == "name_not_found"
        assert str(caught.value) == "cannot resolve gone.test"
    monkeypatch.setattr(socket, "getaddrinfo", failing(socket.EAI_AGAIN))
    with pytest.raises(Unresolvable) as caught:
        resolve_and_pin("slow.test", 443, policy=PUBLIC_POLICY, rule=None)
    assert not caught.value.permanent and caught.value.code == "resolve_failed"


def test_an_unclassifiable_family_is_refused(monkeypatch):
    af_unix = getattr(socket, "AF_UNIX", 1)
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(af_unix, socket.SOCK_STREAM, 0, "", "/tmp/x")])
    _refused("unclassifiable_address", resolve_and_pin, "odd.test", 80,
             policy=PUBLIC_POLICY, rule=None)


def test_locality_table():
    for a in ("127.0.0.1", "::1"):
        assert locality(_ip(a)) == "loopback"
    for a in ("10.1.1.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "fd00::1"):
        assert locality(_ip(a)) == "private"
    assert locality(_ip("8.8.8.8")) == "global"
    for a in ("169.254.169.254", "fe80::1", "0.0.0.0", "224.0.0.1", "198.18.0.1",
              "100.100.100.200"):
        assert locality(_ip(a)) == "refused"


# ---------------------------------------------------------------------------
# The code table
# ---------------------------------------------------------------------------

def test_the_code_tables_cover_every_code():
    assert WIRE_CODES | CLIENT_CODES == CODES
    assert not WIRE_CODES & CLIENT_CODES
    assert set(PROXY_STATUS) == set(SOCKS5_REPLY) == WIRE_CODES
    assert set(CODE_EXCEPTION) == CODES
    # SOCKS5 carries authentication in the method selection or the RFC 1929
    # status, never in a REP; every other wire code has a REP.
    for code in WIRE_CODES:
        if code.startswith("route_auth_"):
            assert SOCKS5_REPLY[code] is None and PROXY_STATUS[code] == 407
        else:
            assert isinstance(SOCKS5_REPLY[code], int), code
    for name in set(CODE_EXCEPTION.values()):
        cls = getattr(pinned_http, name)
        assert issubclass(cls, pinned_http.OutboundError), name
    assert set(pinned_http.EXCEPTION_FOR_CODE) == CODES
    for code in CODES:
        sentence = egress_policy.explain(code)
        assert sentence and "—" not in sentence and "–" not in sentence
        assert "(s)" not in sentence and " -- " not in sentence
        # A sentence that cites a decision cites it through DECISION_REF.
        if "decision" in sentence or "Decision" in sentence:
            assert DECISION_REF in sentence


def test_a_refusal_carries_only_known_codes():
    with pytest.raises(ValueError):
        Refusal("made_up_code")


# ---------------------------------------------------------------------------
# Route data
# ---------------------------------------------------------------------------

def test_the_wire_username_grammar():
    persona, run = str(uuid4()), str(uuid4())
    names = [
        wire_username("persona", persona, f"run:{run}"),
        wire_username("persona", persona, f"act:{run}"),
        wire_username("persona", persona, f"stop:{run}"),
        wire_username("persona", "passive", f"run:{run}"),
        wire_username("integration", "smtp"),
    ] + [wire_username("integration", "lookup-" + "a" * 33, f"{kind}:{run}")
         for kind in egress_policy.INTEGRATION_CONTEXTS]
    for name in names:
        assert not set(name) & set(":@/% \t"), name
        assert len(name) <= egress_policy.WIRE_USERNAME_MAX, name
        claim = parse_wire_username(name)
        assert wire_username(claim.route_kind, claim.name,
                             None if claim.context_kind is None
                             else f"{claim.context_kind}:{claim.context_id}") == name
    assert parse_wire_username("probe.readiness").route_kind == "probe"
    for bad in ("persona:x", "persona.", "integration.UPPER", "integration.a",
                f"persona.{persona}~delivery.{run}", f"integration.smtp~run.{run}",
                f"probe.readiness~check.{run}", f"persona.{persona.upper()}",
                "integration.smtp~run", "x" * 129, "integration.smtp~check.not-a-uuid"):
        _refused("route_auth_failed", parse_wire_username, bad)


def test_an_egress_route_refuses_inconsistent_fields():
    direct = RoutePolicy("integration", admission="local")
    proxied = RoutePolicy("integration", admission="proxy")
    with pytest.raises(ValueError):
        EgressRoute("integration", "smtp", "DIRECT", direct, token=TOKEN)
    with pytest.raises(ValueError):
        EgressRoute("integration", "smtp", "PROXY", proxied, None, "egress-proxy", 3128)
    with pytest.raises(ValueError):
        EgressRoute("integration", "smtp", "PROXY", proxied, None, "egress-proxy", 3128,
                    "t" * 31)
    with pytest.raises(ValueError):
        EgressRoute("integration", "smtp", "PROXY", direct, None, "egress-proxy", 3128, TOKEN)
    with pytest.raises(ValueError):
        EgressRoute("persona", "smtp", "DIRECT", direct)
    with pytest.raises(ValueError):
        EgressRoute("persona", "passive", "PROXY", RoutePolicy("persona", admission="proxy"),
                    None, "egress-proxy", 3128, TOKEN)
    with pytest.raises(ValueError):
        EgressRoute("persona", "not-a-uuid", "DIRECT", PUBLIC_POLICY, RUN)
    with pytest.raises(ValueError):
        EgressRoute("integration", "smtp", "DIRECT", direct, RUN)


def test_the_route_helpers():
    rule = parse_rule("jira.corp.example@10.20.0.0/24:443")
    route = EgressRoute.direct("integration", "jira",
                               RoutePolicy("integration", (rule,), any_public=False))
    delivery = f"delivery:{uuid4()}"
    tagged = route.tagged(delivery)
    assert tagged.context == delivery and route.context is None
    assert tagged.wire_username.startswith("integration.jira~delivery.")
    with pytest.raises(ValueError):
        tagged.tagged(delivery)
    with pytest.raises(ValueError):
        EgressRoute.direct("persona", "passive", PUBLIC_POLICY, context=RUN).tagged(delivery)
    assert route.permits("jira.corp.example", 443)
    assert not route.permits("jira.corp.example", 80)
    assert not route.permits("other.example", 443)
    assert route.private_network("jira.corp.example", 443) == ipaddress.ip_network(
        "10.20.0.0/24")
    public = EgressRoute.direct("integration", "webhook", RoutePolicy(
        "integration", (parse_rule("hooks.example:443"),), any_public=False))
    assert public.private_network("hooks.example", 443) is None
    assert route.rules == (rule,) and route.route_id == "integration:jira"
    assert not route.proxied and not route.boundary_in_force


def test_the_telethon_proxy_dict_is_what_telethon_accepts():
    policy = RoutePolicy("persona", admission="proxy")
    route = EgressRoute("persona", "passive", "PROXY", policy, RUN, "egress-proxy",
                        3128, TOKEN)
    assert route.telethon_proxy() == {
        "proxy_type": "socks5", "addr": "egress-proxy", "port": 3128,
        "username": route.wire_username, "password": TOKEN, "rdns": True}
    assert EgressRoute.direct("persona", "passive", PUBLIC_POLICY,
                              context=RUN).telethon_proxy() is None
    assert TOKEN not in repr(route)
    assert route.proxy_authorization().startswith("Basic ")


def test_family_route_names_take_provider_keys():
    assert egress_policy.family_route_name("lookup-", "virustotal_v3") == "lookup-virustotal-v3"
    # 40 characters is INTEGRATION_NAME (docs/20 section 4.1), which the
    # egress proxy's route table CHECK repeats, so a lookup key is at most 33.
    assert egress_policy.INTEGRATION_NAME == r"^[a-z][a-z0-9-]{1,39}$"
    assert len(egress_policy.family_route_name("lookup-", "a" * 33)) == 40
    for bad in ("", "a" * 34, "a" * 40, "Upper", "bad key"):
        with pytest.raises(ValueError):
            egress_policy.family_route_name("lookup-", bad)


def test_this_module_opens_no_socket_but_its_one_lookup():
    tree = ast.parse(inspect.getsource(egress_policy))
    calls = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = (node.func.attr if isinstance(node.func, ast.Attribute)
                    else getattr(node.func, "id", None))
            calls[name] = calls.get(name, 0) + 1
    for forbidden in ("connect", "create_connection", "urlopen", "socket", "socketpair"):
        assert forbidden not in calls, forbidden
    assert calls.get("getaddrinfo") == 1
    lookup = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "resolve_and_pin")
    assert any(isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "getaddrinfo"
               for n in ast.walk(lookup))
    imported = {alias.name for node in ast.walk(tree)
                if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in node.names} | {
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not imported & {"psycopg", "http.client", "ssl", "os"}, imported
