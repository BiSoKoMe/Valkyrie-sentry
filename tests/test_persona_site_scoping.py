"""A tracker embedded on two unrelated sites must not get the same fake
identity from both - that fake identity would itself be a durable cross-site
tracking id, exactly as correlatable as the real one Nyx is supposed to be
hiding. persona.py used to hand out ONE machine-wide persona to every
destination; this pins the fix: personas are scoped to (first-party,
third-party), stable within that pair, unrelated across pairs.

Every store here is a temporary, isolated file - never the real machine's
persona_seed.json under DATA_DIR.
"""
from __future__ import annotations

import valkyrie.nyx as nyx
import valkyrie.persona as persona_mod
from valkyrie.persona import PersonaStore, persona_for_site


def test_same_pair_is_stable_across_repeated_lookups(tmp_path):
    store = PersonaStore(tmp_path / "seed.json")
    a = store.persona_for("siteA.example", "tracker.example")
    b = store.persona_for("siteA.example", "tracker.example")
    assert a == b


def test_same_tracker_on_different_first_party_sites_gets_different_personas(tmp_path):
    store = PersonaStore(tmp_path / "seed.json")
    on_site_a = store.persona_for("siteA.example", "tracker.example")
    on_site_b = store.persona_for("siteB.example", "tracker.example")
    # The whole point: the SAME tracker cannot correlate "same fake user
    # visited A and B" via the identity Nyx handed it on each site.
    assert on_site_a.advertising_id != on_site_b.advertising_id


def test_different_trackers_on_the_same_site_also_get_different_personas(tmp_path):
    store = PersonaStore(tmp_path / "seed.json")
    tracker_1 = store.persona_for("siteA.example", "tracker1.example")
    tracker_2 = store.persona_for("siteA.example", "tracker2.example")
    assert tracker_1.advertising_id != tracker_2.advertising_id


def test_every_site_scoped_persona_is_still_internally_coherent(tmp_path):
    store = PersonaStore(tmp_path / "seed.json")
    for site, tracker in [("a.example", "t1.example"), ("b.example", "t1.example"),
                          ("a.example", "t2.example")]:
        p = store.persona_for(site, tracker)
        assert p.is_coherent(), p.coherence_errors()


def test_length_prefixed_key_cannot_collide_across_the_join_boundary(tmp_path):
    # Domain names cannot actually contain the separator, but the encoding
    # must not rely on that - defense in depth for whatever a future caller
    # passes.
    store = PersonaStore(tmp_path / "seed.json")
    a = store.persona_for("a", "b|c")
    b = store.persona_for("a|b", "c")
    assert a.advertising_id != b.advertising_id


def test_rotate_invalidates_every_cached_site_persona(tmp_path):
    store = PersonaStore(tmp_path / "seed.json")
    before = store.persona_for("siteA.example", "tracker.example")
    store.rotate()
    after = store.persona_for("siteA.example", "tracker.example")
    assert before.advertising_id != after.advertising_id


def test_site_persona_cache_is_bounded(tmp_path, monkeypatch):
    store = PersonaStore(tmp_path / "seed.json")
    monkeypatch.setattr(PersonaStore, "_MAX_SITE_PERSONAS", 8, raising=True)
    for i in range(50):
        store.persona_for(f"site{i}.example", "tracker.example")
    assert len(store._site_personas) <= 8


def test_persona_for_site_falls_back_to_the_machine_persona_when_unattributed(tmp_path, monkeypatch):
    store = PersonaStore(tmp_path / "seed.json")
    monkeypatch.setattr(persona_mod, "_DEFAULT", store)
    machine = store.persona()
    assert persona_for_site("", "tracker.example").advertising_id == machine.advertising_id
    assert persona_for_site("site.example", "").advertising_id == machine.advertising_id


def test_persona_for_site_matches_the_store_directly(tmp_path, monkeypatch):
    store = PersonaStore(tmp_path / "seed.json")
    monkeypatch.setattr(persona_mod, "_DEFAULT", store)
    assert (persona_for_site("siteA.example", "tracker.example").advertising_id
            == store.persona_for("siteA.example", "tracker.example").advertising_id)


def test_fake_outbound_gives_the_same_tracker_different_fakes_on_different_sites(tmp_path, monkeypatch):
    """End-to-end through the real rewrite path, not just the store."""
    store = PersonaStore(tmp_path / "seed.json")
    monkeypatch.setattr(persona_mod, "_DEFAULT", store)
    tracker_url = "https://tracker.example/collect?adid=550e8400-e29b-41d4-a716-446655440000"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    _u1, body1, faked1 = nyx.fake_outbound(
        "GET", tracker_url, headers, None, first_party_origin="siteA.example")
    _u2, body2, faked2 = nyx.fake_outbound(
        "GET", tracker_url, headers, None, first_party_origin="siteB.example")

    assert faked1 == ["identifier"] and faked2 == ["identifier"]
    assert _u1 != _u2, "the same tracker must see a different fake id per first-party site"

    # But repeating the SAME (site, tracker) pair stays stable.
    _u1_again, _, _ = nyx.fake_outbound(
        "GET", tracker_url, headers, None, first_party_origin="siteA.example")
    assert _u1 == _u1_again
