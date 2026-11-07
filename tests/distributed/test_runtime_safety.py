import pytest
from cryptography.exceptions import InvalidTag

from certify.provision import provision
from node.runtime.config import Settings
from node.runtime.service import Node
from node.runtime.vault import Vault


def settings_and_env(tmp_path, monkeypatch, role="agent"):
    manifest = provision(tmp_path / "nodes")
    cfg = Settings.load(manifest["nodes"][role]["config"])
    for key, value in manifest["nodes"][role]["env"].items():
        monkeypatch.setenv(key, value)
    return cfg, manifest


def test_production_rejects_software_keys_and_missing_bank_controls(
    tmp_path, monkeypatch
):
    cfg, manifest = settings_and_env(tmp_path, monkeypatch)
    values = cfg.model_dump()
    values["mode"] = "production"
    with pytest.raises(ValueError):
        Settings.model_validate(values)


def test_database_is_bound_to_one_institution(tmp_path, monkeypatch):
    cfg, manifest = settings_and_env(tmp_path, monkeypatch)
    first = Node(cfg)
    other = Settings.load(manifest["nodes"]["buyer"]["config"])
    # Accidentally reusing the agent DSN must fail before bank data can be read.
    with pytest.raises(ValueError, match="database belongs to another node"):
        Node(other)
    first.pool.shutdown()
    first.store.engine.dispose()


def test_aead_detects_tamper_and_wrong_record_context():
    vault = Vault(b"a" * 32)
    sealed = vault.seal("own_ssi", {"account": "bank-private"})
    assert "bank-private" not in str(sealed)
    with pytest.raises(InvalidTag):
        vault.open("other_record", sealed)
    with pytest.raises(InvalidTag):
        Vault(b"b" * 32).open("own_ssi", sealed)


def test_restart_marks_inflight_actions_uncertain(tmp_path, monkeypatch):
    cfg, manifest = settings_and_env(tmp_path, monkeypatch)
    node = Node(cfg)
    with node.store.transaction() as s:
        node.store.put(s, "outbox:x", "outbox", {"key": "outbox:x", "state": "SENDING"})
        node.store.put(
            s, "payment:y", "payment", {"payment_id": "y", "state": "EXPORTING"}
        )
    node.pool.shutdown()
    node.store.engine.dispose()
    restarted = Node(cfg)
    with restarted.store.transaction() as s:
        assert restarted.store.get(s, "outbox:x")["state"] == "NEEDS_RECONCILIATION"
        assert restarted.store.get(s, "payment:y")["state"] == "NEEDS_RECONCILIATION"
    assert not restarted.dispatch_one()
    restarted.pool.shutdown()
    restarted.store.engine.dispose()


def test_officer_alias_cannot_defeat_dual_control(tmp_path, monkeypatch):
    cfg, manifest = settings_and_env(tmp_path, monkeypatch)
    data = cfg.model_dump()
    data["officers"][1]["signing_key"] = data["officers"][0]["signing_key"]
    with pytest.raises(ValueError, match="officer keys must be distinct"):
        Settings.model_validate(data)


def test_treasury_floats_and_non_usd_ssi_are_refused(tmp_path, monkeypatch):
    from certify.provision import fixtures
    from node.adapters.models import Ssi
    from node.transport.protocol import ProtocolError

    cfg, manifest = settings_and_env(tmp_path, monkeypatch, role="buyer")
    node = Node(cfg)
    ticket, books = fixtures()
    bad = books["buyer"].copy()
    bad["cash"] = {"available": 49875000000.0}
    with pytest.raises(ProtocolError, match="invalid_treasury_balance"):
        node.validate_import(bad)
    ssi = {**books["buyer"]["own_ssi"], "currency": "EUR"}
    with pytest.raises(ValueError, match="only USD"):
        Ssi.model_validate(ssi)
    node.pool.shutdown()
    node.store.engine.dispose()
