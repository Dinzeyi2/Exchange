from pathlib import Path

import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000):
    """Run the local synthetic sandbox (not a production bank node)."""
    import uvicorn

    from node.api.app import create_app

    uvicorn.run(create_app(), host=host, port=port)


@app.command()
def demo():
    """Run the deterministic synthetic assignment and print measured timings."""
    import json

    from sim.scenario import run

    typer.echo(json.dumps(run(), indent=2))


@app.command()
def certify(output: Path = Path(".local/certification"), reference: bool = False):
    """Run reference checks; report is explicitly NOT a go-live certificate."""
    from certify.runner import run

    report = run(output)
    typer.echo(str(output / "report.json"))
    if not reference and not report["go_live_eligible"]:
        typer.echo(
            "Go-live certification unavailable; see the report for incomplete requirements. Use --reference only for sandbox checks.",
            err=True,
        )
        raise typer.Exit(2)
    if report["status"] != "reference_checks_passed":
        raise typer.Exit(1)


@app.command("verify-audit")
def verify_audit(database: str = "sqlite:///.local/exchange.db"):
    from node.audit.store import Store

    valid = Store(database).verify_audit_chain()
    typer.echo("valid" if valid else "INVALID")
    if not valid:
        raise typer.Exit(1)
