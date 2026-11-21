"""Allow `python -m machina_deid` invocation."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
