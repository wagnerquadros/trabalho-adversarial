"""Launch the arena using Streamlit's command-line entry point."""

from __future__ import annotations

import sys
from importlib.resources import as_file, files


def main() -> None:
    """Forward launcher arguments to Streamlit."""
    from streamlit.web import cli  # noqa: PLC0415 -- optional UI dependency

    with as_file(files("jev_ids.ui").joinpath("app.py")) as script:
        sys.argv[1:] = ["run", str(script), *sys.argv[1:]]
        cli.main()


if __name__ == "__main__":
    main()
