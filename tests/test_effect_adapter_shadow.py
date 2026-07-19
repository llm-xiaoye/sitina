from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from sitina.effects.legacy_adapters import LegacyAdapterKind, ShadowEffectBridge
from sitina.runners.mcp_adapter import McpAdapter
from sitina.runners.provider import AnthropicCompatibleClient, ProviderProfile
from sitina.runners.tool_executor import ToolExecutor


class EffectAdapterShadowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        for name in ("config", "data", "logs", "state", "artifacts", "profiles"):
            (self.home / name).mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.home)

    def test_shadow_bridge_exposes_stable_request_identity_without_invocation(self) -> None:
        called = Mock()
        bridge = ShadowEffectBridge(enabled=True)
        first = bridge.execute(LegacyAdapterKind.TOOL, {"operation": "write", "target": "x"}, called)
        second = bridge.execute(LegacyAdapterKind.TOOL, {"target": "x", "operation": "write"}, called)
        self.assertEqual(first["request_hash"], second["request_hash"])
        self.assertEqual(first["status"], "shadowed")
        called.assert_not_called()

    def test_default_legacy_bridge_preserves_direct_behavior(self) -> None:
        called = Mock(return_value={"status": "ok"})
        result = ShadowEffectBridge(enabled=False).execute(LegacyAdapterKind.MCP, {"tool": "read"}, called)
        self.assertEqual(result, {"status": "ok"})
        called.assert_called_once()

    def test_provider_mcp_and_tool_expose_shadow_entrypoints(self) -> None:
        self.assertTrue(hasattr(AnthropicCompatibleClient(self.home), "effect_shadow_identity"))
        self.assertTrue(hasattr(McpAdapter(self.home), "effect_shadow_identity"))
        self.assertTrue(hasattr(ToolExecutor(self.home), "effect_shadow_identity"))

    def test_acceptance_shadow_never_calls_provider_transport(self) -> None:
        client = AnthropicCompatibleClient(self.home)
        client.effect_shadow = ShadowEffectBridge(enabled=True)
        client._complete_anthropic = Mock(side_effect=AssertionError("must not invoke"))
        profile = ProviderProfile("mock", "https://invalid.example", "secret", "model")
        completion = client.complete_with_metadata(profile, system_prompt="s", user_prompt="u", max_tokens=1)
        self.assertEqual(completion.metadata["effect_shadow"], True)
        client._complete_anthropic.assert_not_called()


if __name__ == "__main__":
    unittest.main()
