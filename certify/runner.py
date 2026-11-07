import json
from pathlib import Path

from node.audit.store import now
from node.signer.backends import SoftwareSigner
from sim.scenario import run as scenario


def run(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    signer = SoftwareSigner.load_or_create(output / "reference-report-key.pem")
    result = scenario()
    report = {
        "scope": "reference sandbox only; NOT go-live certification",
        "ts": now(),
        "status": "reference_checks_passed"
        if result["audit_chain_valid"] and result["state"] == "SETTLED"
        else "failed",
        "result": result,
        "go_live_eligible": False,
        "missing": [
            "bank adapter conformance",
            "all message types across four isolated nodes",
            "production HSM/SSO/KMS",
            "ISO scheme XSDs",
            "hardware/WAN performance",
            "signed PDF report",
        ],
    }
    import base64

    report["public_key"] = base64.b64encode(signer.public_key).decode()
    report["signature"] = signer.sign(report)
    (output / "report.json").write_text(json.dumps(report, indent=2))
    return report
