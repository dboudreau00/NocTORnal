"""Definition integrity: the vocabulary must be internally consistent
before it is allowed to generate anything."""
from noctornal_ontology.definition import EDGE_TYPES, NODE_TYPES, SELECTOR_TYPES


def test_counts_match_seed():
    # +LURE (docs/19), +IMPERSONATES, +4 social-engineering selectors.
    assert len(NODE_TYPES) == 27
    assert len(EDGE_TYPES) == 50
    assert len(SELECTOR_TYPES) == 53


def test_unique_keys():
    for coll in (NODE_TYPES, EDGE_TYPES, SELECTOR_TYPES):
        keys = [x.key for x in coll]
        assert len(keys) == len(set(keys))


def test_no_orphan_node_types():
    """Every decided node type must be reachable by at least one edge, or
    an analyst can create a node nothing may connect to (open question B)."""
    used = set()
    for e in EDGE_TYPES:
        used |= set(e.src_node_types) | set(e.dst_node_types)
    orphans = [n.key for n in NODE_TYPES if n.key not in used]
    assert not orphans, f"node types no edge can touch: {orphans}"


def test_edge_endpoints_are_real_node_types():
    node_keys = {n.key for n in NODE_TYPES}
    for e in EDGE_TYPES:
        assert set(e.src_node_types) <= node_keys, e.key
        assert set(e.dst_node_types) <= node_keys, e.key
        assert e.src_node_types and e.dst_node_types, e.key


def test_default_sign_in_range():
    assert all(e.default_sign in (-1, 0, 1) for e in EDGE_TYPES)


def test_categories_are_closed_set():
    assert {n.category for n in NODE_TYPES} == {"ACTOR", "ARTEFACT", "CONTEXT"}


def test_undirected_edges_have_symmetric_labels_and_endpoints():
    """An undirected edge read backwards is the same statement, so its
    inverse label and endpoint sets must be identical."""
    for e in EDGE_TYPES:
        if not e.is_directed:
            assert e.display_name == e.inverse_name, e.key
            assert set(e.src_node_types) == set(e.dst_node_types), e.key


def test_invariant_9_tox():
    """TOX_PK is the only strong Tox selector; the 76-hex observed form
    is weak because its nospam rotates."""
    by_key = {s.key: s for s in SELECTOR_TYPES}
    assert by_key["TOX_PK"].is_strong
    assert by_key["TOX_PK"].normaliser == "tox_pubkey"
    assert not by_key["TOX_ID_FULL"].is_strong
    assert "TOX_ID" not in by_key  # collapsed pre-Phase-0 (decision 15)


def test_recycled_display_identifiers_are_weak():
    """Invariant 9 generally: rotatable/recycled identifiers must never
    be merge-strong."""
    by_key = {s.key: s for s in SELECTOR_TYPES}
    for weak in ("TELEGRAM_USER", "HANDLE", "WIRE_HANDLE", "TOX_ID_FULL", "DOMAIN"):
        assert not by_key[weak].is_strong, weak


def test_collision_prone_selectors_are_weak():
    """Unscoped or attacker-controlled values must never auto-merge:
    forum UIDs are per-venue, PDB paths and cert CNs are free text."""
    by_key = {s.key: s for s in SELECTOR_TYPES}
    for weak in ("FORUM_UID", "PDB_PATH", "CODESIGN_CN"):
        assert not by_key[weak].is_strong, weak


def test_bipartite_and_structural_edges_are_not_social():
    """Affiliation/plumbing edges distort centrality if counted as social
    ties; their signal is the analysis-time projection (docs/01)."""
    by_key = {e.key: e for e in EDGE_TYPES}
    for structural in ("POSTS_ON", "PARTICIPANT_IN", "PARTICIPATED_IN",
                       "SAME_DEVICE_AS", "CO_POSTED_IN", "SHARED_INFRA",
                       "SAME_AS", "ALIAS_OF", "ATTRIBUTED_TO"):
        assert not by_key[structural].is_social_tie, structural
