
from certify.distributed import run_processes


def test_four_independent_processes_settlement_and_security(tmp_path):
    report = run_processes(tmp_path / "nodes")
    assert set(report["states"].values()) == {"CLOSED"}
    assert report["register_conserved"] and report["seller_payment_reconciled"]
    assert report["duplicate_trade_refused"] and report["all_audit_chains_valid"]
    assert len(report["security_checks"]) >= 10
    assert all(report["security_checks"].values())
    assert report["signature_verification"]["verified_node_envelopes"] > 0
    assert report["signature_verification"]["verified_officer_approvals"] >= 13
    assert report["timings"]["entry_to_ready_wall_ms"] <= 30000
    assert report["timings"]["funds_to_receipts_wall_ms"] <= 10000
