"""Entry point used when building the standalone program (Sentinel.exe)."""
import sys

from sentinel.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
