"""icli: a non-interactive command-line interface to IDA Pro (icli(1))."""

__version__ = "0.1.1"


def main() -> None:
    from .cli.frozen import setup

    setup()
    from .cli.main import entry

    entry()
