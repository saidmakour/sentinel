from __future__ import annotations

from sentinel.cli.app import app
from sentinel.log import setup_logging


def main() -> None:
    setup_logging()
    app()


if __name__ == "__main__":
    main()
