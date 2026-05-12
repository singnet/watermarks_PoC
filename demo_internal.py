"""Backwards-compatible shim for the old ``demo_internal.py`` script.

The implementation has moved into the ``openwater_mk`` package; this file
delegates to ``openwater_mk.cli.main(['demo', ...])``. New work should use
the ``openwater`` console entrypoint directly.
"""
from __future__ import annotations

import sys

from openwater_mk.pipeline import run_demo  # re-export for legacy tests
from openwater_mk.cli import main as _cli_main


def main(argv: list[str] | None = None) -> int:
    """Run the demo subcommand. Mirrors the old script's exit-code semantics."""
    args = ["demo"] + (argv if argv is not None else sys.argv[1:])
    return _cli_main(args)


if __name__ == "__main__":
    sys.exit(main())
