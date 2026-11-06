"""Entry point when invoked via python -m notary."""

import sys
from notary.cli import main

if __name__ == "__main__":
    sys.exit(main())

