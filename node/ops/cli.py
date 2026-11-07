from pathlib import Path

import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def serve(config: Path = typer.Option(..., exists=True, readable=True)):
    """Start one institution's peer and officer listeners from explicit configuration."""
    import asyncio

    from node.runtime.runner import run

    asyncio.run(run(config))


@app.command()
def certify(
    output: Path = Path(".local/certification"),
    deployment: str = "processes",
    acceptance: bool = False,
):
    """Run the real distributed node runtime against controlled acceptance fixtures."""
    from certify.runner import run

    report = run(output, deployment=deployment)
    typer.echo(str(output / "report.json"))
    if not acceptance and not report["go_live_eligible"]:
        typer.echo(
            "Go-live certification unavailable; see the report for incomplete requirements. Use --acceptance for fixture-based distributed checks.",
            err=True,
        )
        raise typer.Exit(2)
    if report["status"] != "distributed_acceptance_passed":
        raise typer.Exit(1)


@app.command("verify-audit")
def verify_audit(database: str = "sqlite:///.local/exchange.db"):
    from node.audit.store import Store

    valid = Store(database).verify_audit_chain()
    typer.echo("valid" if valid else "INVALID")
    if not valid:
        raise typer.Exit(1)


@app.command("migrate")
def migrate():
    """Provision this node schema using the separately authorized migration DB role."""
    import os

    from node.audit.store import Store

    store = Store(os.environ["EXCHANGE_DATABASE_URL"], initialize=True)
    store.engine.dispose()
    typer.echo(
        "Node schema initialized; configure a least-privilege runtime role before serving."
    )


if __name__ == "__main__":
    app()
