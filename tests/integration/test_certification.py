import base64
import json

from certify.runner import run
from node.identity.crypto import verify


def test_reference_report_signature(tmp_path):
    report = run(tmp_path)
    assert report["go_live_eligible"] is False
    assert report["status"] == "distributed_acceptance_passed"
    assert json.loads((tmp_path / "report.json").read_text()) == report
    verify(
        base64.b64decode(report["public_key"]),
        {k: v for k, v in report.items() if k != "signature"},
        report["signature"],
    )


def test_cli_refuses_go_live_certification(tmp_path):
    from typer.testing import CliRunner

    from node.ops.cli import app

    runner = CliRunner()
    args = ["certify", "--output", str(tmp_path)]
    assert runner.invoke(app, args).exit_code == 2
    assert runner.invoke(app, args + ["--acceptance"]).exit_code == 0
