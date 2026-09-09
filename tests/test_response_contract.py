"""Real response adapters, isolated intelligence and temporary lease storage.

No host controls, sockets, services or real intelligence state are used.
"""
import copy
import sqlite3
from unittest.mock import Mock

import pytest

from valkyrie.edr import cascade, leases
from valkyrie.edr.plugins import PluginContext
from valkyrie.edr.response import BlockDomainResponder, ResponseManager
from valkyrie.edr.schema import normalize_response_status
from valkyrie.edr.store import EdrStore
from valkyrie.store import Store


@pytest.fixture
def dispatch(tmp_path, monkeypatch):
    ledger = leases.LeaseRegistry(tmp_path / "leases.json")
    budget = cascade.CascadeBudget()
    monkeypatch.setattr(leases, "registry", lambda: ledger)
    monkeypatch.setattr(cascade, "budget", lambda: budget)
    intel = Mock()
    intel.apply_response_block.return_value = True
    registry = Mock()
    registry.responder_for.return_value = BlockDomainResponder()
    manager = ResponseManager(registry, PluginContext(intelligence=intel))
    return manager, ledger, budget, intel, registry


def test_real_block_is_leased_and_expiry_is_recorded_once(dispatch, tmp_path):
    manager, ledger, budget, intel, _ = dispatch
    action = manager.respond("block_domain", "malicious.example", dry_run=False)
    assert action.status == "succeeded"
    intel.apply_response_block.assert_called_once()
    lease = ledger.get("block_domain", "malicious.example")
    assert lease is not None
    persisted_expiry = intel.apply_response_block.call_args.args[1]
    assert abs(persisted_expiry - lease.expires_at) < 0.1
    assert len(budget) == 1
    restored = leases.LeaseRegistry(tmp_path / "leases.json")
    assert restored.get("block_domain", "malicious.example").lease_id == lease.lease_id
    result = manager.sweep_expired_leases(now=lease.expires_at + 1)
    assert [a.status for a in result] == ["succeeded"]
    intel.release_response_block.assert_called_once()
    assert ledger.get("block_domain", "malicious.example") is None
    assert manager.sweep_expired_leases(now=lease.expires_at + 2) == []
    assert len(leases.LeaseRegistry(tmp_path / "leases.json")) == 0


def test_failed_reversal_retains_due_lease(dispatch):
    manager, ledger, _, intel, _ = dispatch
    manager.respond("block_domain", "malicious.example", dry_run=False)
    lease = ledger.get("block_domain", "malicious.example")
    intel.release_response_block.side_effect = RuntimeError("storage unavailable")
    assert manager.sweep_expired_leases(now=lease.expires_at + 1)[0].status == "failed"
    assert ledger.get("block_domain", "malicious.example") == lease


def test_dry_run_and_failed_apply_do_not_create_lease(dispatch):
    manager, ledger, budget, intel, _ = dispatch
    assert manager.respond("block_domain", "malicious.example").status == "dry_run"
    intel.apply_response_block.assert_not_called()
    intel.apply_response_block.side_effect = RuntimeError("storage unavailable")
    assert manager.respond("block_domain", "malicious.example", dry_run=False).status == "failed"
    assert len(ledger) == len(budget) == 0


@pytest.mark.parametrize("status", ["ok", "success", "completed", "succeeded"])
def test_legacy_plugins_use_the_same_success_contract(dispatch, status):
    manager, ledger, _, _, registry = dispatch
    registry.responder_for.return_value = Mock(execute=Mock(return_value=(status, "applied")))
    assert manager.respond("block_domain", "malicious.example", dry_run=False).status == "succeeded"
    assert ledger.get("block_domain", "malicious.example") is not None


@pytest.mark.parametrize("status", [None, "applied?", {}, 1])
def test_unknown_status_is_not_success(status):
    with pytest.raises(ValueError):
        normalize_response_status(status)


class _AuditStore:
    def __init__(self, fail_calls=()):
        self.fail_calls = set(fail_calls)
        self.calls = 0
        self.rows = {}
        self.history = []

    def record_response(self, action):
        self.calls += 1
        if self.calls in self.fail_calls:
            raise OSError("audit database unavailable")
        snapshot = copy.deepcopy(action.to_dict())
        self.rows[action.id] = snapshot
        self.history.append(snapshot)


def _audited_manager(store, responder=None):
    registry = Mock()
    registry.responder_for.return_value = responder or Mock(
        execute=Mock(return_value=("succeeded", "enforced")))
    return ResponseManager(registry, PluginContext(), edr_store=store), registry


def test_preflight_audit_failure_prevents_host_response():
    store = _AuditStore(fail_calls={1, 2})
    responder = Mock(execute=Mock(return_value=("succeeded", "must not run")))
    manager, _ = _audited_manager(store, responder)

    action = manager.respond("block_domain", "malicious.example", dry_run=False)

    assert action.status == "failed"
    assert action.audit_state == "unavailable"
    assert "response not executed" in action.result
    responder.execute.assert_not_called()


def test_final_audit_failure_retains_pending_preflight_row():
    store = _AuditStore(fail_calls={2})
    manager, registry = _audited_manager(store)

    action = manager.respond("unblock_domain", "malicious.example", dry_run=False)

    assert action.status == "succeeded"
    assert action.audit_state == "final_update_failed"
    assert "pending preflight row retained" in action.result
    registry.responder_for.return_value.execute.assert_called_once()
    assert store.rows[action.id]["status"] == "pending"
    assert store.rows[action.id]["audit_state"] == "preflight_persisted"


def test_successful_real_response_persists_preflight_then_final_result():
    store = _AuditStore()
    manager, _ = _audited_manager(store)

    action = manager.respond("unblock_domain", "malicious.example", dry_run=False)

    assert action.audit_state == "final_persisted"
    assert [row["status"] for row in store.history] == ["pending", "succeeded"]
    assert [row["audit_state"] for row in store.history] == [
        "preflight_persisted", "final_persisted"]
    assert store.history[0]["id"] == store.history[1]["id"] == action.id


def test_lease_persistence_failure_rolls_back_enforcement(monkeypatch):
    store = _AuditStore()
    forward = Mock(execute=Mock(return_value=("succeeded", "block applied")))
    reverse = Mock(execute=Mock(return_value=("succeeded", "block removed")))
    registry = Mock()
    registry.responder_for.side_effect = lambda action: {
        "block_domain": forward, "unblock_domain": reverse}.get(action)
    manager = ResponseManager(registry, PluginContext(), edr_store=store)
    broken_leases = Mock()
    broken_leases.grant.side_effect = leases.LeaseError("disk unavailable")
    monkeypatch.setattr(leases, "registry", lambda: broken_leases)

    action = manager.respond("block_domain", "malicious.example", dry_run=False)

    assert action.status == "failed"
    assert "rolled back immediately" in action.result
    forward.execute.assert_called_once()
    reverse.execute.assert_called_once()
    assert store.rows[action.id]["status"] == "failed"


def test_lease_registry_keeps_memory_consistent_when_writes_fail(tmp_path, monkeypatch):
    registry = leases.LeaseRegistry(tmp_path / "leases.json")
    monkeypatch.setattr(
        registry, "_save", Mock(side_effect=leases.LeaseError("disk unavailable")))

    with pytest.raises(leases.LeaseError):
        registry.grant("block_domain", "malicious.example")

    assert registry.get("block_domain", "malicious.example") is None
    assert len(registry) == 0


def test_existing_response_table_migrates_audit_state(tmp_path):
    db_path = tmp_path / "existing.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE edr_responses (
                id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
                action TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '',
                operator TEXT NOT NULL DEFAULT 'local',
                dry_run INTEGER NOT NULL DEFAULT 1,
                incident_id TEXT NOT NULL DEFAULT '')
        """)
    store = Store(db_path=db_path)
    store.start()
    try:
        edr = EdrStore(store)
        edr.init_schema()
        with sqlite3.connect(db_path) as conn:
            columns = {row[1] for row in conn.execute(
                "PRAGMA table_info(edr_responses)").fetchall()}
        assert "audit_state" in columns
    finally:
        store.stop()
