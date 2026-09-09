"""Temporary DNS response blocks stay bounded and preserve learned evidence."""

import time

from valkyrie.intelligence import memory as memory_module
from valkyrie.intelligence.memory import IntelligenceMemory
from valkyrie.store import Store


def _memory(tmp_path):
    store = Store(db_path=tmp_path / "events.db")
    store.start()
    memory = IntelligenceMemory(store)
    memory.start()
    return store, memory


def test_response_block_survives_restart_and_can_be_released(tmp_path):
    store, memory = _memory(tmp_path)
    expires_at = time.time() + 60
    assert memory.apply_response_block("beacon.example", expires_at)
    assert memory.check("beacon.example") == "bad"
    assert memory.reason_for("beacon.example") == "edr:temporary_response_block"

    restarted = IntelligenceMemory(store)
    restarted.start()
    assert restarted.check("beacon.example") == "bad"
    assert restarted.stats()["active_response_blocks"] == 1

    restarted.release_response_block("beacon.example")
    assert restarted.check("beacon.example") is None
    reloaded = IntelligenceMemory(store)
    reloaded.start()
    assert reloaded.check("beacon.example") is None
    store.stop()


def test_release_does_not_downgrade_independent_threat_evidence(tmp_path):
    store, memory = _memory(tmp_path)
    memory.remember_bad("confirmed-c2.example", reason="signed threat feed")
    assert memory.apply_response_block("confirmed-c2.example", time.time() + 60)
    memory.release_response_block("confirmed-c2.example")
    assert memory.check("confirmed-c2.example") == "bad"
    assert memory.reason_for("confirmed-c2.example") == "signed threat feed"
    store.stop()


def test_expired_and_absurd_blocks_fail_safe(tmp_path, monkeypatch):
    store, memory = _memory(tmp_path)
    now = time.time()
    monkeypatch.setattr(memory_module.time, "time", lambda: now)
    assert memory.apply_response_block("short-lived.example", now + 30)
    assert memory.check("short-lived.example") == "bad"

    monkeypatch.setattr(memory_module.time, "time", lambda: now + 31)
    assert memory.check("short-lived.example") is None
    assert memory.stats()["active_response_blocks"] == 0

    try:
        memory.apply_response_block("too-long.example", now + 90_000)
    except ValueError as exc:
        assert "expiry" in str(exc)
    else:
        raise AssertionError("an unbounded response block was accepted")
    store.stop()


def test_popular_and_malformed_domains_are_refused(tmp_path):
    store, memory = _memory(tmp_path)
    assert memory.apply_response_block("google.com", time.time() + 60) is False
    for domain in ("", "bad..example", "-bad.example", "bad_.example"):
        try:
            memory.apply_response_block(domain, time.time() + 60)
        except ValueError:
            continue
        raise AssertionError(f"malformed domain accepted: {domain!r}")
    store.stop()
