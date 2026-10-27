from __future__ import annotations

import os as _sitina_os
import pwd as _sitina_pwd
import sys as _sitina_sys
_SITINA_ACCOUNT_HOME = _sitina_pwd.getpwuid(_sitina_os.getuid()).pw_dir

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sitina.legacy import fence


class CleanAcceptanceFenceRoutingTests(unittest.TestCase):
    def test_copytree_audit_checks_destination_not_readonly_source(self) -> None:
        home = Path((_SITINA_ACCOUNT_HOME + '/SitinaHub'))
        source = home / "core"
        destination = home / "acceptance/clean-test/core"
        with patch.object(fence, "_guard_home", home), patch.object(fence, "_marker_present", return_value=True):
            fence._audit_guard("shutil.copytree", (str(source), str(destination)))

    def test_copytree_destination_outside_bplus_plane_is_denied(self) -> None:
        home = Path((_SITINA_ACCOUNT_HOME + '/SitinaHub'))
        with tempfile.TemporaryDirectory() as directory:
            destination = home / "logs/recreated-legacy-tree"
            with patch.object(fence, "_guard_home", home), patch.object(fence, "_marker_present", return_value=True):
                with self.assertRaises(fence.LegacyWriteDenied):
                    fence._audit_guard("shutil.copytree", (directory, str(destination)))


if __name__ == "__main__":
    unittest.main()
