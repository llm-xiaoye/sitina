"""Sitina-native global Skills, Plugins, tools, and autonomous model loop."""

from sitina.extensions.manager import ExtensionManager
from sitina.extensions.runtime import AutonomousRuntime
from sitina.extensions.spec import ExtensionSpecError, PluginManifest, SkillDefinition

__all__ = [
    "AutonomousRuntime",
    "ExtensionManager",
    "ExtensionSpecError",
    "PluginManifest",
    "SkillDefinition",
]
