"""Exits sealed for the egress proxy alone (S22-4 B,
2026-09-24). Pure: no database and no socket."""
from __future__ import annotations

from uuid import uuid4

import pytest

from egress_support import FINGERPRINT_KEY, keys
from noctornal_api.security import egress_seal
from noctornal_api.security.egress_seal import ExitEndpoint, ExitRing, SealError

END = ExitEndpoint("gw.residential.example", 8080, "user-country-gb", "s3cret-pass")


def _ring(retired=False):
    return ExitRing.from_env(keys(retired=retired))


def test_seal_then_open_round_trips_for_its_profile_and_exit_kind():
    ring = _ring()
    pid = uuid4()
    blob, kid = egress_seal.seal(ring.public(), profile_id=pid, exit_kind="SOCKS5",
                                 endpoint=END)
    assert kid == ring.active_id and kid.startswith("egress:") and len(kid) == 23
    assert ring.open(blob, key_id_=kid, profile_id=pid, exit_kind="SOCKS5") == END
    assert b"s3cret-pass" not in blob and b"residential" not in blob


def test_a_blob_moved_to_another_profile_or_exit_kind_does_not_open():
    ring = _ring()
    pid = uuid4()
    blob, kid = egress_seal.seal(ring.public(), profile_id=pid, exit_kind="HTTPS",
                                 endpoint=END)
    with pytest.raises(SealError):
        ring.open(blob, key_id_=kid, profile_id=uuid4(), exit_kind="HTTPS")
    # An https exit relabelled http in the table would send the credentials
    # in clear: the binding refuses to open it.
    with pytest.raises(SealError):
        ring.open(blob, key_id_=kid, profile_id=pid, exit_kind="HTTP")


def test_a_flipped_byte_fails_to_open():
    ring = _ring()
    pid = uuid4()
    blob, kid = egress_seal.seal(ring.public(), profile_id=pid, exit_kind="SOCKS5",
                                 endpoint=END)
    broken = bytearray(blob)
    broken[-1] ^= 1
    with pytest.raises(SealError):
        ring.open(bytes(broken), key_id_=kid, profile_id=pid, exit_kind="SOCKS5")


def test_a_retired_key_still_opens_and_an_unknown_one_refuses():
    from egress_support import old_seal_public
    ring = _ring(retired=True)
    old = egress_seal.load_public(old_seal_public())
    pid = uuid4()
    blob, kid = egress_seal.seal(old, profile_id=pid, exit_kind="SOCKS5", endpoint=END)
    assert kid != ring.active_id and ring.holds(kid)
    assert ring.open(blob, key_id_=kid, profile_id=pid, exit_kind="SOCKS5") == END
    with pytest.raises(SealError, match="does not hold"):
        _ring().open(blob, key_id_=kid, profile_id=pid, exit_kind="SOCKS5")


def test_key_ids_derive_from_the_public_key():
    ring = _ring()
    public = egress_seal.public_from_env(keys())
    assert egress_seal.key_id(public) == ring.active_id


def test_the_endpoint_repr_hides_the_password():
    assert "s3cret-pass" not in repr(END)
    assert "gw.residential.example" in repr(END)


def test_the_fingerprint_covers_the_user_name_and_exit_kind_and_not_the_password():
    base = egress_seal.fingerprint(FINGERPRINT_KEY, "SOCKS5", END)
    other_user = ExitEndpoint(END.host, END.port, "user-country-us", END.password)
    other_pass = ExitEndpoint(END.host, END.port, END.username, "rotated-pass")
    assert egress_seal.fingerprint(FINGERPRINT_KEY, "SOCKS5", other_user) != base
    assert egress_seal.fingerprint(FINGERPRINT_KEY, "SOCKS5", other_pass) == base
    # Changing the transport of an otherwise identical exit is a widening.
    assert egress_seal.fingerprint(FINGERPRINT_KEY, "HTTP", END) != \
        egress_seal.fingerprint(FINGERPRINT_KEY, "HTTPS", END)


def test_the_fingerprint_uses_its_own_key_not_the_client_key():
    env = keys()
    env_rotated = dict(env, NOCTORNAL_EGRESS_CLIENT_KEY="Q" * 43 + "=")
    first = egress_seal.fingerprint(egress_seal.fingerprint_key(env), "SOCKS5", END)
    second = egress_seal.fingerprint(egress_seal.fingerprint_key(env_rotated), "SOCKS5", END)
    assert first == second


@pytest.mark.parametrize("endpoint, kind, words", [
    (ExitEndpoint("gw.example", 0), "SOCKS5", "port"),
    (ExitEndpoint("not a host", 1080), "SOCKS5", "host"),
    (ExitEndpoint("gw.example", 3128, "a:b", "pw"), "HTTP", "colon"),
    (ExitEndpoint("gw.example", 1080, "u" * 256, "pw"), "SOCKS5", "255"),
    (ExitEndpoint("gw.example", 1080, "user", ""), "SOCKS5", "both"),
    (ExitEndpoint("gw.example", 1080, "us\ner", "pw"), "SOCKS5", "printable"),
    (ExitEndpoint("gw.example", 1080), "DIRECT", "Only"),
])
def test_an_unusable_exit_is_refused_before_it_is_sealed(endpoint, kind, words):
    with pytest.raises(SealError, match=words):
        egress_seal.seal(_ring().public(), profile_id=uuid4(), exit_kind=kind,
                         endpoint=endpoint)


def test_without_hpke_both_halves_refuse_with_the_shown_gap(monkeypatch):
    ring = _ring()
    pid = uuid4()
    blob, kid = egress_seal.seal(ring.public(), profile_id=pid, exit_kind="SOCKS5",
                                 endpoint=END)
    monkeypatch.setattr(egress_seal, "_hpke", None)
    with pytest.raises(SealError) as sealing:
        egress_seal.seal(ring.public(), profile_id=pid, exit_kind="SOCKS5", endpoint=END)
    assert str(sealing.value) == egress_seal.NO_HPKE
    with pytest.raises(SealError) as opening:
        ring.open(blob, key_id_=kid, profile_id=pid, exit_kind="SOCKS5")
    assert str(opening.value) == egress_seal.NO_HPKE


def test_sealing_without_the_public_key_names_the_setting():
    with pytest.raises(SealError) as caught:
        egress_seal.public_from_env({})
    assert str(caught.value) == egress_seal.NO_PUBLIC_KEY


def test_keygen_gives_a_pair_whose_id_matches_the_ring():
    made = egress_seal.keygen()
    ring = ExitRing.from_env({egress_seal.SEAL_KEY_ENV: made[egress_seal.SEAL_KEY_ENV]})
    assert ring.active_id == made["key_id"]
    assert egress_seal.key_id(egress_seal.load_public(made[egress_seal.SEAL_PUBLIC_ENV])) \
        == made["key_id"]


def test_a_malformed_retired_key_is_named_by_position_never_by_value():
    env = dict(keys(), NOCTORNAL_EGRESS_SEAL_KEY_RETIRED="notbase64!!")
    with pytest.raises(SealError) as caught:
        ExitRing.from_env(env)
    assert "entry 1" in str(caught.value) and "notbase64" not in str(caught.value)
