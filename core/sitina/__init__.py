"""Sitina local multi-agent harness."""

import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from sitina.legacy.fence import install_legacy_mutation_guard

__version__ = "0.1.0"

_runtime_home = Path(os.environ.get("SITINA_HOME", "/Users/moss/SitinaHub")).expanduser()
_production_home = Path("/Users/moss/SitinaHub")
if (
    os.environ.get("SITINA_CONTROL_PLANE_READONLY") != "1"
    # Production is identified by its fixed authority root and must never
    # probe a clean-Acceptance marker.  Disposable roots retain the marker
    # check that prevents installing a mutation guard in acceptance mode.
    and (
        _runtime_home.resolve(strict=False) == _production_home
        or not (_runtime_home / ".sitina-clean-acceptance-v1").is_file()
    )
):
    install_legacy_mutation_guard(_runtime_home)
