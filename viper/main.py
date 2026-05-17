import click
from viper.logger import enable_console_logging
from viper.core.pipeline import Pipeline


@click.group()
def cli() -> None:
    """Viper CLI entrypoint."""
    enable_console_logging()


@cli.command()
@click.option(
    "--repo", 
    required=True, 
    help="Target repository path or GitHub URL."
)
def analyze(repo: str) -> None:
    """Run analysis stage."""
    pipeline = Pipeline(repo=repo)
    pipeline.analyze()


@cli.command()
@click.option(
    "--repo", 
    required=True, 
    help="Target repository path or GitHub URL."
)
def run(repo: str) -> None:
    """Run full pipeline."""
    pipeline = Pipeline(repo=repo)
    pipeline.run()


if __name__ == "__main__":
    cli()