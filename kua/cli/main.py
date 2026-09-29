"""CLI entrypoint for kua (k8s-upgrade-agent)."""

import importlib.metadata

import typer
from rich.console import Console

app = typer.Typer(
    name="kua",
    help="AI-assisted agent that plans, gates, executes, and verifies Kubernetes version upgrades.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def version() -> None:
    """Print the version of kua."""
    try:
        ver = importlib.metadata.version("k8s-upgrade-agent")
    except importlib.metadata.PackageNotFoundError:
        ver = "0.1.0.dev0"
    console.print(f"kua {ver}")


@app.command()
def scan() -> None:
    """Scan an EKS cluster for upgrade readiness (placeholder)."""
    console.print("not implemented")
    raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
