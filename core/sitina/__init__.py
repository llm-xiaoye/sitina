"""Sitina local multi-agent harness.

Package import is deliberately side-effect free.  The retired Legacy/B+
writer fence is installed only by an explicit Legacy command boundary; Code
Mode owns an independent runtime context and must not inherit that process
global fence merely because the package was imported.
"""

import sys

sys.dont_write_bytecode = True

__version__ = "0.1.0"
