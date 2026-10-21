"""icli: a non-interactive command-line interface to IDA Pro (icli(1))."""

__version__ = "0.1.0"


def main() -> None:
    from .cli.main import entry

    entry()
